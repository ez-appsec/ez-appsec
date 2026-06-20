# True negative: explicit permit list (safe)
class UsersController < ApplicationController
  def create
    # ok: ez-rails-mass-assignment-permit-all
    User.create(params.require(:user).permit(:name, :email))
  end
end
