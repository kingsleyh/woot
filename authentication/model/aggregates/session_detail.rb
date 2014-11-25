require_relative '../../repository/users'
require_relative '../../repository/sessions'
require_relative '../../repository/identities'

class SessionDetail

  def initialize(session_id)
    @session_id = session_id
  end

  def user
    session.empty? ? empty : Users.find(where(id:equals(session.get.head.user_id))).get_or_else(empty)
  end

  def session
    Sessions.find(where(session_id:equals(@session_id))).get_or_else(empty)
  end

  def identities
    session.empty? ? empty : Identities.find(where(user_id:equals(session.get.head.user_id))).get_or_else(empty)
  end

end

