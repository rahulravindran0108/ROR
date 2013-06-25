class ZombiesController < ApplicationController
  # GET /zombies
  # GET /zombies.json
  def index
    @zombies = Zombie.all

    respond_to do |format|
      format.html # index.html.erb
      format.json { render json: @zombies }
    end
  end
 
  def signin
    @zombie = Zombie.new
  end

  def signedout
    session[:zombie_id] = nil    
    redirect_to :root
  end

  def login
    username_or_email = params[:zombie][:username]
    password = params[:zombie][:password]

    if username_or_email.rindex('@')
      email=username_or_email
      zombie = Zombie.authenticate_by_email(email, password)
    else
      username=username_or_email
      zombie = Zombie.authenticate_by_username(username, password)
    end

    if zombie
      session[:zombie_id] = zombie.id
      flash[:notice] = 'Welcome.'
      redirect_to :root
    else
      render :action => "signin"
    end
  end

  # GET /zombies/1
  # GET /zombies/1.json
  def show
    @zombie = Zombie.find(params[:id])

    respond_to do |format|
      format.html # show.html.erb
      format.json { render json: @zombie }
    end
  end

  # GET /zombies/new
  # GET /zombies/new.json
  def new
    @zombie = Zombie.new

    respond_to do |format|
      format.html # new.html.erb
      format.json { render json: @zombie }
    end
  end

  # GET /zombies/1/edit
  def edit
    @zombie = Zombie.find(params[:id])
  end

  # POST /zombies
  # POST /zombies.json
  def create
    @zombie = Zombie.new(params[:zombie])

    respond_to do |format|
      if @zombie.save
        format.html { redirect_to @zombie, notice: 'Zombie was successfully created.' }
        format.json { render json: @zombie, status: :created, location: @zombie }
      else
        format.html { render action: "new" }
        format.json { render json: @zombie.errors, status: :unprocessable_entity }
      end
    end
  end

  # PUT /zombies/1
  # PUT /zombies/1.json
  def update
    @zombie = Zombie.find(params[:id])

    respond_to do |format|
      if @zombie.update_attributes(params[:zombie])
        format.html { redirect_to @zombie, notice: 'Zombie was successfully updated.' }
        format.json { head :ok }
      else
        format.html { render action: "edit" }
        format.json { render json: @zombie.errors, status: :unprocessable_entity }
      end
    end
  end

  # DELETE /zombies/1
  # DELETE /zombies/1.json
  def destroy
    @zombie = Zombie.find(params[:id])
    @zombie.destroy

    respond_to do |format|
      format.html { redirect_to zombies_url }
      format.json { head :ok }
    end
  end
end
