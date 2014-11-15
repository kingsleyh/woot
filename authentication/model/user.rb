class User < Record

  def initialize(email, first_name, last_name, password_hash, password_salt)
    super(email: email, first_name: first_name, last_name: last_name, password_hash: password_hash, password_salt: password_salt)
  end

  def self.def
    definition(:users, keyword(:email), keyword(:first_name), keyword(:last_name),keyword(:password_hash),keyword(:password_salt))
  end

end
