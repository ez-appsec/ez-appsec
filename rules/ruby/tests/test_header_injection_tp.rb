# True positive: user input in response header
class LanguageController < ApplicationController
  def set_lang
    # ruleid: ez-rails-header-injection
    response.headers["Content-Language"] = params[:lang]
  end
end
