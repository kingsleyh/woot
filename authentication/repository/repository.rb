require 'singleton'
require 'lazy_records'
require 'adapters/sqlite3'

class Repository

  include Singleton

  attr_reader :records

  def initialize
    @records = SqlRecords.new(Sqlite3.new(File.dirname(__FILE__) + '/../../db/development.sqlite3',true))
  end

end
