class Identity < Record

  def initialize(user_id, provider, uid)
    super(user_id: user_id, provider: provider, uid:uid)
  end

  def self.def
    definition(:identities, keyword(:user_id), keyword(:provider), keyword(:uid))
  end

end
