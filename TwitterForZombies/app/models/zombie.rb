class Zombie < ActiveRecord::Base
  attr_accessible :email, :username, :password, :password_confirmation
  attr_accessor :password
  before_save :encrypt_password

  validates_confirmation_of :password
  validates_presence_of :password, :on => :create
  validates_presence_of :email, :on => :create
  validates_presence_of :username, :on => :create
  validates_uniqueness_of :email
  validates_uniqueness_of :username

  def self.authenticate_by_email(email, password)
    zombie = find_by_email(email)
    if zombie && zombie.password_hash == BCrypt::Engine.hash_secret(password, zombie.password_salt)
      zombie
    else
      nil
    end
  end

  def self.authenticate_by_username(username, password)
    zombie = find_by_username(username)
    if zombie && zombie.password_hash == BCrypt::Engine.hash_secret(password, zombie.password_salt)
      zombie
    else
      nil
    end
  end

  def encrypt_password
    if password.present?
      self.password_salt = BCrypt::Engine.generate_salt
      self.password_hash = BCrypt::Engine.hash_secret(password, password_salt)
    end
  end
end
