require 'lazy_records'
require_relative '../authentication/db_connection'
require 'bcrypt'
require 'after_do'

class Validations

  def self.has_uniqueness?(table, fields={},message=nil)
    errors = []
    outcome = fields.map do |k, v|
      result = option(SqlVirtualRecords.new(DbConnection.instance.connection).get(table, where(k => equals(v)))).is_some?
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


class User < BaseModel

  before :save do |*, user|
    user.encrypt_record
    user.validate
  end

  def initialize(*values)
    super(:users, values)
  end

  def encrypt_record
    password_salt = BCrypt::Engine.generate_salt
    password_hash = BCrypt::Engine.hash_secret(@record.password, password_salt)
    @record = vrecord(:email, @record.email, :password_hash, password_hash, :password_salt, password_salt)
  end

  def self.find(selection=nil)
    option(SqlVirtualRecords.new(DbConnection.instance.connection).get(:users, selection))
  end

  def validate
    add_validation Validations.not_empty?(email: @record.email, password: @values[:password], password_confirmation: @values[:password_confirmation])
    add_validation Validations.has_uniqueness?(:users, email: @record.email)
    add_validation Validations.field_values_match?(:password, :password_confirmation, @values[:password], @values[:password_confirmation], "Password and Password Confirmation must match!")
  end


end


records = SqlVirtualRecords.new(DbConnection.instance.connection)
# p records.sql_query("select * from users").entries
# p records.sql_query("select * from users where email = 'test@test.com'").entries
