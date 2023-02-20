class User < ApplicationRecord



    validates :username, :session_token, :password_digest, presence: true
    validates :username, :session_token, uniqueness: true

    before_validation :ensure_session_token


    def generate_unique_random_token
        token = SecureRandom::urlsafe_base64
        while User.exists?(session_token: token)
            token = SecureRandom::urlsafe_base64
        end
    end


    def ensure_session_token
        self.session_token ||= generate_unique_random_token
    end

    





end