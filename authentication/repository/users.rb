require_relative '../repository/repository'
require_relative '../model/user'
require_relative 'validations'
require 'bcrypt'
require 'singleton'

class Users

  def self.create(email, password, password_confirmation)
    encrypted_user = encrypt_record(email, password)
    v = validate(email, password, password_confirmation)
    Repository.instance.records.add(User.def, sequence(encrypted_user)) if v.is_valid?
    v
  end

  def self.find(selection=nil)
    option(Repository.instance.records.get(User.def, selection))
  end

  def self.all
    Repository.instance.records.get(User.def)
  end

  private

  def self.encrypt_record(email, password)
    password_salt = BCrypt::Engine.generate_salt
    password_hash = BCrypt::Engine.hash_secret(password, password_salt)
    User.new(email, 'first', 'last', password_hash, password_salt)
  end


  def self.validate(email, password, password_confirmation)
    v = Validations.new
    v.add_validation Validations.not_empty?(email: email, password: password, password_confirmation: password_confirmation)
    v.add_validation Validations.has_uniqueness?(Users,email: email)
    v.add_validation Validations.field_values_match?(:password, :password_confirmation, password, password_confirmation, 'Password and Password Confirmation must match!')
    v
  end

end

