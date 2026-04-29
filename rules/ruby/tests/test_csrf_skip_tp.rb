# True positive: CSRF protection disabled
class ApiController < ApplicationController
  # ruleid: ez-rails-csrf-skip
  skip_before_action :verify_authenticity_token
end
