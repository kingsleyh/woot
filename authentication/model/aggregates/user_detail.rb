require_relative '../../repository/users'
require_relative '../../repository/sessions'
require_relative '../../repository/identities'

class UserDetail

  def initialize(user_id)
    @user_id = user_id
  end

  def user
    Users.find(where(id:equals(@user_id))).get_or_else(empty)
  end

  def sessions
    Sessions.find(where(user_id:equals(@user_id))).get_or_else(empty)
  end

  def identities
    Identities.find(where(user_id:equals(@user_id))).get_or_else(empty)
  end

  def current_session(session_id)
    sessions = Sessions.find(where(session_id:equals(session_id)))
    sessions.is_some? ? sessions.get.head.session_id : ''
  end

end

