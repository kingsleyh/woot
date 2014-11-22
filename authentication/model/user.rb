require_relative '../repository/sessions'

class User < Record

  def initialize(email, password_hash, password_salt)
    super(email: email, password_hash: password_hash, password_salt: password_salt)
  end

  def self.def
    definition(:users, keyword(:email), keyword(:password_hash), keyword(:password_salt))
  end

  def method_missing(method_sym, *arguments, &block)
    p 'hello'
    if method_sym.to_s =~ /^sessions/
      sessions
    else
      super
    end
  end

  def sessions
    p 'yay'
    Sessions.find(where(id:equals(self.get_hash[:id]))).get_or_else(empty)
  end

end
