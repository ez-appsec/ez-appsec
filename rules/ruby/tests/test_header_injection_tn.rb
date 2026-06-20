# True negative: hardcoded header value (safe)
class LanguageController < ApplicationController
  def set_lang
    # ok: ez-rails-header-injection
    response.headers["Content-Language"] = "en-US"
  end
end
