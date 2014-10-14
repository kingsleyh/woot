require 'singleton'
require 'lazy_records'
require 'adapters/sqlite3'

class DbConnection
  include Singleton

  attr_reader :connection

  def initialize
    @connection = Sqlite3.new(File.dirname(__FILE__) + '/db/development.sqlite3',true)
  end


end