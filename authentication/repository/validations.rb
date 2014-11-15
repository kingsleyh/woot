class Validations

  def initialize
    @errors = []
  end

  def add_validation(validation)
    validated = validation
    @errors << validated.second unless validated.first
  end

  def is_valid?
    @errors.flatten.empty?
  end

  def errors
    @errors.flatten
  end

  def self.has_uniqueness?(item,fields={},message=nil)
    errors = []
    outcome = fields.map do |k, v|
      result = option(item.find(where(k => equals(v)))).is_some?
      errors << (message.nil? ? "#{k} must be unique" : message) if result
      result
    end.include?(true)
    pair(!outcome, errors)
  end

  def self.field_values_match?(field1, field2, value1, value2, message=nil)
    errors = []
    result = value1 == value2
    errors << (message.nil? ? "#{field2} must match #{field1}" : message) unless result
    pair(result, errors)
  end

  def self.not_empty?(h={},messages={})
    errors = []
    outcome = h.each do |k,v|
      result = v.empty?
      errors << (messages[k].nil? ? "#{k} must not be empty" : messages[k]) if result
    end.include?(true)
    pair(outcome,errors)
  end

end