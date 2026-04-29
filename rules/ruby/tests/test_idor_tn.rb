# True negative: scoped to current_user (safe)
class InvoicesController < ApplicationController
  def show
    # ok: ez-rails-idor-find
    @invoice = current_user.invoices.find(params[:id])
    render json: @invoice
  end
end
