class SessionsTable < ActiveRecord::Migration
  def change
    create_table :sessions do |t|
      t.string :user_id
      t.string :session_id
      t.string :start_time
      t.string :ip_address
      t.string :user_agent
      t.string :login_method
    end
  end
end
