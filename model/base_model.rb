require 'lazy_records'
require_relative '../authentication/db_connection'
require 'bcrypt'
require 'after_do'
require_relative 'validations'

class BaseModel
  extend AfterDo

  def initialize(table, values)
    @table = table
    @values = sequence(values).to_map
    @records = SqlVirtualRecords.new(DbConnection.instance.connection)
    @record = Record.new(@values)
    @errors = []
  end

  def self.find(table, selection=nil)
    SqlVirtualRecords.new(DbConnection.instance.connection).get(table, selection)
  end

  def record
    @record
  end

  def record=(record)
    @record = record
  end

  def save
    is_valid? ? (@records.add(@table, sequence(@record)); true) : false
  end

  def errors
    @errors.flatten
  end

  def is_valid?
    errors.empty?
  end

  protected

  def add_validation(validation)
    validated = validation
    @errors << validated.second unless validated.first
  end

end