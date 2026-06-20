# True negative: CSRF protection enabled (safe)
class ApplicationController < ActionController::Base
  # ok: ez-rails-csrf-skip
  protect_from_forgery with: :exception
end
