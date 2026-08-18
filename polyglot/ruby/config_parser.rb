require 'yaml'
require 'json'
require 'date'
require 'uri'

module Dastlite
  # Base exception for all config-related errors
  class ConfigError < StandardError; end
  
  # Specific error types with helpful messages
  class MissingRequiredField < ConfigError
    def initialize(field:, context: "config")
      super("Missing required field '#{field}' in #{context}")
    end
  end

  class InvalidFormat < ConfigError
    def initialize(field:, expected:, actual:)
      msg = "Invalid format for '#{field}': expected #{expected}, got #{actual.inspect}"
      super(msg)
    end
  end

  class SecretNotResolved < ConfigError
    def initialize(secret_name:)
      super("Secret '#{secret_name}' not found in environment or vault")
    end
  end

  # Represents a single target URL/domain to scan
  Target = Struct.new(:url, :method, :headers) do
    def self.from_config(config)
      url = config['url'] || raise(InvalidFormat, new: 'url', expected: String, actual: config['url'])
      
      method = (config['method'] || :get).to_sym
      
      headers = if h = config['headers'] && !h.empty?
        h.transform_keys { |k| k.to_s.delete_prefix('X-').delete_prefix('x-') }
          .transform_values { |v| v.is_a?(String) ? v : YAML.safe_load(v, symbolize_names: true) }
      else
        {}
      end
      
      new(url, method, headers)
    end
    
    def to_safeguarded_url
      uri = URI.parse(self.url)
      "#{uri.scheme}://#{uri.host}#{uri.path}"
    end
  end

  # Authentication configuration
  AuthConfig = Struct.new(:type, :credentials) do
    def self.from_config(config)
      type = (config['type'] || 'basic').to_sym
      
      credentials = if c = config['credentials'] && !c.empty?
        case type
        when :basic
          { user: c['user'], pass: c['pass'] }
        when :bearer, :oauth2
          { token: c['token'] || c['access_token'] }
        when :api_key
          { key: c['key'], header: (c['header'] || 'X-API-Key') }
        else
          raise InvalidFormat.new(field: 'auth.type', expected: [:basic, :bearer, :oauth2, :api_key].join(', '), actual: type)
        end
      else
        {}
      end
      
      new(type, credentials)
    end
    
    def to_safeguarded_hash
      hash = { type: self.type.to_s }
      
      case self.type
      when :basic
        hash[:user] = self.credentials[:user] || ''
        hash[:pass] = self.credentials[:pass] || ''
      when :bearer, :oauth2
        hash[:token] = self.credentials[:token] || ''
      when :api_key
        hash[:key] = self.credentials[:key] || ''
        hash[:header] = self.credentials[:header] || 'X-API-Key'
      end
      
      hash
    end
  end

  # A single DAST rule from a ruleset
  Rule = Struct.new(:id, :name, :enabled, :params) do
    def self.from_config(config)
      id = config['id'] || raise(InvalidFormat.new(field: 'rule.id', expected: String, actual: config['id']))
      
      enabled = (config['enabled'] != false)
      
      params = if p = config['params'] && !p.empty?
        YAML.safe_load(p, symbolize_names: true) || {}
      else
        {}
      end
      
      new(id, config['name'], enabled, params)
    end
    
    def to_safeguarded_hash
      hash = { id: self.id, name: self.name, enabled: self.enabled }
      
      if !self.params.empty?
        hash[:params] = self.params.transform_keys(&:to_s).transform_values do |v|
          v.is_a?(String) ? YAML.dump(v) : v
        end
      end
      
      hash
    end
  end

  # A complete ruleset configuration
  RulesetConfig = Struct.new(:name, :version, :rules) do
    def self.from_config(config)
      name = config['name'] || 'default'
      version = (config['version'] || '1.0').to_s
      
      rules = if r = config['rules'] && !r.empty?
        r.map { |c| Rule.from_config(c) }
      else
        []
      end
      
      new(name, version, rules)
    end
    
    def to_safeguarded_hash
      hash = { name: self.name, version: self.version, rules: self.rules.map(&:to_safeguarded_hash) }
      hash
    end
  end

  # Main configuration parser and validator
  class Parser
    DEFAULT_CONFIG = {
      targets: [],
      auth: { type: :bearer },
      rulesets: [
        { name: 'default', version: '1.0', rules: [] }
      ],
      output: { format: :sarif, deduplicate: true },
      environment: { variables: {}, secrets: {} }
    }.freeze

    # Initialize with optional default config path
    def initialize(default_config_path = nil)
      @default_config = DEFAULT_CONFIG.dup
      
      if default_config_path && File.exist?(default_config_path)
        begin
          loaded = YAML.safe_load(File.read(default_config_path), symbolize_names: true)
          merge_configs(@default_config, loaded)
        rescue StandardError => e
          raise ConfigError.new("Failed to load default config from #{default_config_path}: #{e.message}")
        end
      end
    end

    # Parse and validate the main configuration file
    def parse(config_path)
      unless File.exist?(config_path)
        raise ConfigError.new("Config file not found: #{config_path}")
      end
      
      begin
        loaded = YAML.safe_load(File.read(config_path), symbolize_names: true) || DEFAULT_CONFIG.dup
        
        # Merge with defaults (user config overrides defaults)
        merge_configs(@default_config, loaded)
        
        # Validate and resolve secrets
        validate_and_resolve_secrets!
        
        @parsed = ConfigObject.new(merged)
      rescue StandardError => e
        raise ConfigError.new("Failed to parse config: #{e.message}")
      end
      
      @parsed
    end

    private

    def merge_configs(base, override)
      base.each do |key, value|
        if override.key?(key) && !override[key].nil?
          if value.is_a?(Hash) && override[key].is_a?(Hash)
            merge_configs(value, override[key])
          else
            base[key] = override[key]
          end
        end
      end
      
      # Apply overrides in reverse order (last wins for scalars)
      override.each do |key, value|
        if !base.key?(key) || (base[key].nil? && !value.nil?)
          base[key] = value
        elsif value.is_a?(Hash) && key == 'rulesets'
          # Merge rulesets arrays
          base[key] = merge_arrays(base[key], override[key])
        end
      end
      
      base
    end

    def merge_arrays(defaults, overrides)
      defaults.map do |d|
        o = overrides.find { |r| r['name'] == d['name'] } || {}
        ConfigObject.new(merge_configs(d, o))
      end
    end

    def validate_and_resolve_secrets!
      # Resolve environment variables in config values
      resolve_env_vars!(@parsed)
      
      # Validate required fields
      validate_targets!
      validate_rulesets!
    end

    def resolve_env_vars!(obj, prefix = '')
      obj.each do |key, value|
        next unless value.is_a?(String) || (value.is_a?(Hash) && !value.empty?)
        
        # Support ${VAR} and #{ENV['VAR']} syntax
        resolved_value = if value.match?(/\$\{([^}]+)\}/) || value.match?(/#\{\w+\}/)
          value.gsub(/\$|\{|\}/) { |m| ENV[m] || m }
        else
          value
        end
        
        # Recurse into nested hashes
        if resolved_value.is_a?(Hash) && !resolved_value.empty?
          resolve_env_vars!(ConfigObject.new(resolved_value), "#{prefix}.#{key}")
        elsif resolved_value.is_a?(Array)
          resolved_value.map! { |v| v.is_a?(String) ? v.gsub(/\$|\{|\}/) { |m| ENV[m] || m } : v }
        end
        
        obj[key] = resolved_value if resolved_value != value
      end
    rescue StandardError => e
      raise ConfigError.new("Failed to resolve environment variables: #{e.message}")
    end

    def validate_targets!
      targets = @parsed.targets || []
      
      unless targets.is_a?(Array)
        raise InvalidFormat.new(field: 'targets', expected: Array, actual: targets.class)
      end
      
      targets.each_with_index do |target, i|
        t = Target.from_config(target)
        
        unless URI.parse(t.url).is_a?(URI::HTTP) || URI.parse(t.url).is_a?(URI::HTTPS)
          raise InvalidFormat.new(field: "targets[#{i}].url", expected: 'http/https URL', actual: t.url)
        end
        
        @parsed.targets[i] = t if targets.is_a?(Array)
      end
      
      @parsed.targets || []
    end

    def validate_rulesets!
      rulesets = @parsed.rulesets || []
      
      unless rulesets.is_a?(Array)
        raise InvalidFormat.new(field: 'rulesets', expected: Array, actual: rulesets.class)
      end
      
      rulesets.each_with_index do |rs, i|
        r = RulesetConfig.from_config(rs)
        
        @parsed.rulesets[i] = r if rulesets.is_a?(Array)
      end
      
      @parsed.rulesets || []
    end

    # Wrapper class for the parsed configuration
    ConfigObject = Struct.new(:targets, :auth, :rulesets, :output, :environment) do
      def to_safeguarded_hash
        hash = {
          targets: self.targets.map(&:to_safeguarded_url),
          auth: self.auth.to_safeguarded_hash,
          rulesets: self.rulesets.map(&:to_safeguarded_hash),
          output: { format: self.output[:format], deduplicate: self.output[:deduplicate] }
        }
        
        if !self.environment.empty?
          hash[:environment] = {
            variables: self.environment[:variables],
            secrets: self.environment[:secrets]
          }
        end
        
        hash
      end

      def to_sarif_metadata
        # Return metadata for SARIF output
        {
          tool: { name: 'dastlite', version: '1.0' },
          driver_version: "config/#{self.rulesets.map(&:version).join(', ')}",
          targets: self.targets.map(&:to_safeguarded_url),
          auth_type: self.auth[:type].to_s,
          ruleset_count: self.rulesets.size
        }
      end

      def to_json(only_metadata: false)
        data = only_metadata ? to_sarif_metadata : to_safeguarded_hash
        JSON.generate(data)
      end
    end
  end
end