require_relative '../repository/repository'
require_relative '../model/identity'
require_relative 'validations'

class Identities

  def self.create(user_id, provider, uid)
    Repository.instance.records.add(Identity.def, sequence(Identity.new(user_id,provider,uid)))
  end

  def self.find(selection=nil)
    option(Repository.instance.records.get(Identity.def, selection))
  end

  def self.remove(selection=nil)
    Repository.instance.records.remove(Identity.def, selection)
  end

  def self.all
    Repository.instance.records.get(Identity.def)
  end

end

