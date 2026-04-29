# True negative: JSON.parse is safe
class DataController < ApplicationController
  def import
    # ok: ez-rails-insecure-deserialization
    obj = JSON.parse(params[:data])
    render json: obj
  end
end
