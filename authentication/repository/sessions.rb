require_relative '../repository/repository'
require_relative '../model/session'

class Sessions

  def self.create(user_id, session_id, start_time, ip_address, user_agent, login_method)
    Repository.instance.records.add(Session.def, sequence(Session.new(user_id, session_id, start_time, ip_address,
                                                          user_agent,login_method)))
  end

  def self.find(selection=nil)
    option(Repository.instance.records.get(Session.def, selection))
  end

  def self.remove(selection=nil)
    Repository.instance.records.remove(Session.def, selection)
  end

  def self.all
    Repository.instance.records.get(Session.def)
  end

end

