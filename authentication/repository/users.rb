require_relative '../repository/repository'
require_relative '../model/user'
require_relative 'validations'
require 'bcrypt'
require 'singleton'

class Users

  def self.create(email, password, password_confirmation)
    encrypted_user = encrypt_record(email, password)
    v = validate_on_create(email, password, password_confirmation)
    Repository.instance.records.add(User.def, sequence(encrypted_user)) if v.is_valid?
    v
  end

  def self.update(user_id,email, password, password_confirmation)
    v = validate_on_update(email, password, password_confirmation)
    if email.is_some?
      Repository.instance.records.set(User.def, where(id: equals(user_id)), keyword(:email), email.get) if v.is_valid?
    end
    if password.is_some?
      crypted = encrypt_password(password.get)
      Repository.instance.records.set(User.def, where(id: equals(user_id)), keyword(:password_hash), crypted[:password_hash],
      keyword(:password_salt), crypted[:password_salt]) if v.is_valid?
    end
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
    crypted = encrypt_password(password)
    User.new(email, crypted[:password_hash], crypted[:password_salt])
  end

  def self.encrypt_password(password)
    password_salt = BCrypt::Engine.generate_salt
    {password_salt: password_salt, password_hash: BCrypt::Engine.hash_secret(password, password_salt)}
  end


  def self.validate_on_create(email, password, password_confirmation)
    v = Validations.new
    v.add_validation Validations.not_empty?(email: email, password: password, password_confirmation: password_confirmation)
    v.add_validation Validations.has_uniqueness?(Users, email: email)
    v.add_validation Validations.field_values_match?(:password, :password_confirmation, password, password_confirmation, 'Password and Password Confirmation must match!')
    v
  end

  def self.validate_on_update(email, password, password_confirmation)
    v = Validations.new
    if email.is_some?
      v.add_validation Validations.not_empty?(email: email.get)
      v.add_validation Validations.has_uniqueness?(Users, email: email.get)
    end
    if password.is_some?
      v.add_validation Validations.not_empty?(password: password.get, password_confirmation: password_confirmation.get_or_else(''))
      v.add_validation Validations.field_values_match?(:password, :password_confirmation, password.get, password_confirmation.get_or_else(''), 'Password and Password Confirmation must match!')
    end
    v
  end

end

