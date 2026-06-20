# True positive: mass assignment via permit!
class UsersController < ApplicationController
  def create
    # ruleid: ez-rails-mass-assignment-permit-all
    User.create(params.permit!)
  end
end
