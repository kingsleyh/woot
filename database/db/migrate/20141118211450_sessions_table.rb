class SessionsTable < ActiveRecord::Migration
  def change
    create_table :sessions do |t|
      t.string :user_id
      t.string :session_id
      t.string :start_time
    end
  end
end
