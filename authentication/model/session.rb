class Session < Record

  def initialize(user_id, session_id, start_time)
    super(user_id: user_id, session_id: session_id, start_time: start_time)
  end

  def self.def
    definition(:sessions, keyword(:user_id), keyword(:session_id), keyword(:start_time))
  end

end
