# True positive: IDOR via direct find without scoping
class InvoicesController < ApplicationController
  def show
    # ruleid: ez-rails-idor-find
    @invoice = Invoice.find(params[:id])
    render json: @invoice
  end
end
