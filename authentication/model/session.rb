class Session < Record

  def initialize(user_id, session_id, start_time,ip_address,user_agent,login_method)
    super(user_id: user_id, session_id: session_id, start_time: start_time, ip_address:ip_address,
    user_agent:user_agent,login_method:login_method)
  end

  def self.def
    definition(:sessions, keyword(:user_id), keyword(:session_id), keyword(:start_time),keyword(:ip_address),
               keyword(:user_agent),keyword(:login_method))
  end

end
