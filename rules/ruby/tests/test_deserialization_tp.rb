# True positive: Marshal.load with user input
class DataController < ApplicationController
  def import
    # ruleid: ez-rails-insecure-deserialization
    obj = Marshal.load(params[:data])
    render json: obj
  end
end
