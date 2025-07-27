import os
import boto3
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import uuid

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cropyield_secret_key_2024')

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')

# Table Names
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'CropYieldUsers')
FARMS_TABLE_NAME = os.environ.get('FARMS_TABLE_NAME', 'CropYieldFarms')
YIELD_DATA_TABLE_NAME = os.environ.get('YIELD_DATA_TABLE_NAME', 'CropYieldData')
WEATHER_TABLE_NAME = os.environ.get('WEATHER_TABLE_NAME', 'WeatherData')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
sns = boto3.client('sns', region_name=AWS_REGION_NAME)

# DynamoDB Tables
users_table = dynamodb.Table(USERS_TABLE_NAME)
farms_table = dynamodb.Table(FARMS_TABLE_NAME)
yield_data_table = dynamodb.Table(YIELD_DATA_TABLE_NAME)
weather_table = dynamodb.Table(WEATHER_TABLE_NAME)

# ---------------------------------------
# Utility Functions
# ---------------------------------------
def send_sns_alert(message, subject):
    """Send SNS alert for crop anomalies or forecasts"""
    if ENABLE_SNS and SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=message,
                Subject=subject
            )
            return True
        except Exception as e:
            print(f"SNS Error: {e}")
            return False
    return False

def analyze_yield_anomaly(current_yield, historical_avg):
    """Detect yield anomalies"""
    if historical_avg == 0:
        return False, 0
    
    deviation = ((current_yield - historical_avg) / historical_avg) * 100
    
    # Alert if yield drops more than 20% below historical average
    if deviation < -20:
        return True, deviation
    return False, deviation

def login_required(f):
    """Decorator for routes that require login"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """Decorator for admin-only routes"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_role') != 'admin':
            flash('Admin access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ---------------------------------------
# Authentication Routes
# ---------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'farmer')  # farmer or admin
        farm_name = data.get('farm_name', '')
        location = data.get('location', '')
        
        if not all([username, email, password]):
            flash('All fields are required')
            return render_template('register.html') if request.form else jsonify({'error': 'All fields required'}), 400
        
        # Check if user exists
        try:
            response = users_table.get_item(Key={'email': email})
            if 'Item' in response:
                flash('User already exists')
                return render_template('register.html') if request.form else jsonify({'error': 'User exists'}), 409
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        
        # Create new user
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)
        
        try:
            users_table.put_item(Item={
                'user_id': user_id,
                'email': email,
                'username': username,
                'password': hashed_password,
                'role': role,
                'farm_name': farm_name,
                'location': location,
                'created_at': datetime.now().isoformat(),
                'is_active': True
            })
            
            flash('Registration successful')
            return redirect(url_for('login')) if request.form else jsonify({'message': 'User created', 'user_id': user_id}), 201
                
        except Exception as e:
            flash('Registration failed')
            return render_template('register.html') if request.form else jsonify({'error': str(e)}), 500
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        email = data.get('email')
        password = data.get('password')
        
        if not all([email, password]):
            flash('Email and password required')
            return render_template('login.html') if request.form else jsonify({'error': 'Missing credentials'}), 400
        
        try:
            response = users_table.get_item(Key={'email': email})
            if 'Item' not in response:
                flash('Invalid credentials')
                return render_template('login.html') if request.form else jsonify({'error': 'Invalid credentials'}), 401
            
            user = response['Item']
            
            if not user.get('is_active', True):
                flash('Account deactivated')
                return render_template('login.html') if request.form else jsonify({'error': 'Account deactivated'}), 401
            
            if check_password_hash(user['password'], password):
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['user_role'] = user.get('role', 'farmer')
                session['farm_name'] = user.get('farm_name', '')
                
                return redirect(url_for('dashboard')) if request.form else jsonify({
                    'message': 'Login successful',
                    'user': {
                        'user_id': user['user_id'],
                        'username': user['username'],
                        'role': user.get('role', 'farmer')
                    }
                }), 200
            else:
                flash('Invalid credentials')
                return render_template('login.html') if request.form else jsonify({'error': 'Invalid credentials'}), 401
                
        except Exception as e:
            flash('Login failed')
            return render_template('login.html') if request.form else jsonify({'error': str(e)}), 500
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully')
    return redirect(url_for('index'))

# ---------------------------------------
# Dashboard Routes
# ---------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    user_role = session.get('user_role', 'farmer')
    
    if user_role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('farmer_dashboard'))

@app.route('/farmer/dashboard')
@login_required
def farmer_dashboard():
    try:
        # Get user's farm data
        farms_response = farms_table.query(
            IndexName='UserIndex',
            KeyConditionExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']}
        )
        farms = farms_response.get('Items', [])
        
        # Get recent yield data
        yield_response = yield_data_table.query(
            IndexName='UserIndex',
            KeyConditionExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': session['user_id']},
            Limit=10,
            ScanIndexForward=False
        )
        recent_yields = yield_response.get('Items', [])
        
        return render_template('farmer_dashboard.html', 
                             farms=farms, 
                             recent_yields=recent_yields)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}')
        return render_template('farmer_dashboard.html', farms=[], recent_yields=[])

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    try:
        # Get all farms overview
        farms_response = farms_table.scan()
        all_farms = farms_response.get('Items', [])
        
        # Get recent yield data across all farms
        yield_response = yield_data_table.scan(Limit=20)
        all_yields = yield_response.get('Items', [])
        
        # Calculate statistics
        total_farms = len(all_farms)
        total_yield_records = len(all_yields)
        
        # Get low-performing farms (for alerts)
        low_yield_farms = []
        for farm in all_farms:
            avg_yield = farm.get('avg_yield', 0)
            if avg_yield < 50:  # Threshold for low yield
                low_yield_farms.append(farm)
        
        return render_template('admin_dashboard.html', 
                             total_farms=total_farms,
                             total_yield_records=total_yield_records,
                             low_yield_farms=low_yield_farms,
                             recent_yields=all_yields[:10])
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}')
        return render_template('admin_dashboard.html', 
                             total_farms=0, 
                             total_yield_records=0,
                             low_yield_farms=[],
                             recent_yields=[])

# ---------------------------------------
# Farm Management Routes
# ---------------------------------------
@app.route('/farms')
@login_required
def farms():
    try:
        if session.get('user_role') == 'admin':
            # Admin sees all farms
            response = farms_table.scan()
        else:
            # Farmers see only their farms
            response = farms_table.query(
                IndexName='UserIndex',
                KeyConditionExpression='user_id = :user_id',
                ExpressionAttributeValues={':user_id': session['user_id']}
            )
        
        farms_list = response.get('Items', [])
        return render_template('farms.html', farms=farms_list)
    except Exception as e:
        flash(f'Error loading farms: {str(e)}')
        return render_template('farms.html', farms=[])

@app.route('/farm/add', methods=['GET', 'POST'])
@login_required
def add_farm():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        farm_name = data.get('farm_name')
        location = data.get('location')
        area_acres = data.get('area_acres')
        crop_type = data.get('crop_type')
        soil_type = data.get('soil_type', '')
        
        if not all([farm_name, location, area_acres, crop_type]):
            flash('All required fields must be filled')
            return render_template('add_farm.html') if request.form else jsonify({'error': 'Missing required fields'}), 400
        
        farm_id = str(uuid.uuid4())
        
        try:
            farms_table.put_item(Item={
                'farm_id': farm_id,
                'user_id': session['user_id'],
                'farm_name': farm_name,
                'location': location,
                'area_acres': float(area_acres),
                'crop_type': crop_type,
                'soil_type': soil_type,
                'created_at': datetime.now().isoformat(),
                'avg_yield': 0,
                'last_updated': datetime.now().isoformat()
            })
            
            flash('Farm added successfully')
            return redirect(url_for('farms')) if request.form else jsonify({'message': 'Farm added', 'farm_id': farm_id}), 201
                
        except Exception as e:
            flash('Failed to add farm')
            return render_template('add_farm.html') if request.form else jsonify({'error': str(e)}), 500
    
    return render_template('add_farm.html')

# ---------------------------------------
# Yield Data Routes
# ---------------------------------------
@app.route('/farm/<farm_id>/yield/add', methods=['GET', 'POST'])
@login_required
def add_yield_data(farm_id):
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        harvest_date = data.get('harvest_date')
        yield_amount = data.get('yield_amount')
        quality_grade = data.get('quality_grade', 'A')
        notes = data.get('notes', '')
        
        if not all([harvest_date, yield_amount]):
            flash('Harvest date and yield amount are required')
            return render_template('add_yield.html', farm_id=farm_id) if request.form else jsonify({'error': 'Missing required fields'}), 400
        
        yield_id = str(uuid.uuid4())
        current_yield = float(yield_amount)
        
        try:
            # Get farm details for anomaly detection
            farm_response = farms_table.get_item(Key={'farm_id': farm_id})
            farm = farm_response.get('Item', {})
            historical_avg = farm.get('avg_yield', 0)
            
            # Check for yield anomalies
            is_anomaly, deviation = analyze_yield_anomaly(current_yield, historical_avg)
            
            # Add yield data
            yield_data_table.put_item(Item={
                'yield_id': yield_id,
                'farm_id': farm_id,
                'user_id': session['user_id'],
                'harvest_date': harvest_date,
                'yield_amount': current_yield,
                'quality_grade': quality_grade,
                'notes': notes,
                'is_anomaly': is_anomaly,
                'deviation_percent': deviation,
                'created_at': datetime.now().isoformat()
            })
            
            # Update farm's average yield
            if historical_avg > 0:
                new_avg = (historical_avg + current_yield) / 2
            else:
                new_avg = current_yield
                
            farms_table.update_item(
                Key={'farm_id': farm_id},
                UpdateExpression='SET avg_yield = :avg, last_updated = :updated',
                ExpressionAttributeValues={
                    ':avg': new_avg,
                    ':updated': datetime.now().isoformat()
                }
            )
            
            # Send alert for anomalies
            if is_anomaly:
                alert_message = f"Yield Anomaly Detected!\nFarm: {farm.get('farm_name', 'Unknown')}\nExpected: {historical_avg:.2f}\nActual: {current_yield:.2f}\nDeviation: {deviation:.1f}%"
                send_sns_alert(alert_message, "Crop Yield Anomaly Alert")
            
            flash('Yield data added successfully')
            return redirect(url_for('farm_details', farm_id=farm_id)) if request.form else jsonify({'message': 'Yield data added', 'yield_id': yield_id}), 201
                
        except Exception as e:
            flash('Failed to add yield data')
            return render_template('add_yield.html', farm_id=farm_id) if request.form else jsonify({'error': str(e)}), 500
    
    # Get farm details
    try:
        farm_response = farms_table.get_item(Key={'farm_id': farm_id})
        farm = farm_response.get('Item')
        if not farm:
            flash('Farm not found')
            return redirect(url_for('farms'))
    except Exception as e:
        flash('Error loading farm')
        return redirect(url_for('farms'))
    
    return render_template('add_yield.html', farm=farm)

@app.route('/farm/<farm_id>')
@login_required
def farm_details(farm_id):
    try:
        # Get farm details
        farm_response = farms_table.get_item(Key={'farm_id': farm_id})
        farm = farm_response.get('Item')
        
        # Get yield history for this farm
        yield_response = yield_data_table.query(
            IndexName='FarmIndex',
            KeyConditionExpression='farm_id = :farm_id',
            ExpressionAttributeValues={':farm_id': farm_id},
            ScanIndexForward=False
        )
        yield_history = yield_response.get('Items', [])
        
        return render_template('farm_details.html', farm=farm, yield_history=yield_history)
    except Exception as e:
        flash(f'Error loading farm details: {str(e)}')
        return redirect(url_for('farms'))

# ---------------------------------------
# Weather Data Routes
# ---------------------------------------
@app.route('/weather/add', methods=['GET', 'POST'])
@login_required
def add_weather_data():
    if request.method == 'POST':
        data = request.form if request.form else request.get_json()
        
        location = data.get('location')
        date = data.get('date')
        temperature = data.get('temperature')
        humidity = data.get('humidity')
        rainfall = data.get('rainfall', 0)
        
        if not all([location, date, temperature, humidity]):
            flash('All required fields must be filled')
            return render_template('add_weather.html') if request.form else jsonify({'error': 'Missing required fields'}), 400
        
        weather_id = str(uuid.uuid4())
        
        try:
            weather_table.put_item(Item={
                'weather_id': weather_id,
                'location': location,
                'date': date,
                'temperature': float(temperature),
                'humidity': float(humidity),
                'rainfall': float(rainfall),
                'recorded_by': session['user_id'],
                'created_at': datetime.now().isoformat()
            })
            
            flash('Weather data added successfully')
            return redirect(url_for('dashboard')) if request.form else jsonify({'message': 'Weather data added', 'weather_id': weather_id}), 201
                
        except Exception as e:
            flash('Failed to add weather data')
            return render_template('add_weather.html') if request.form else jsonify({'error': str(e)}), 500
    
    return render_template('add_weather.html')
# Add these routes to your Flask backend code

# ---------------------------------------
# Weather Viewing Routes
# ---------------------------------------

@app.route('/weather')
@login_required
def weather_list():
    try:
        if session.get('user_role') == 'admin':
            # Admin sees all weather data
            response = weather_table.scan()
        else:
            # Farmers see only their weather data
            response = weather_table.scan(
                FilterExpression='recorded_by = :user_id',
                ExpressionAttributeValues={':user_id': session['user_id']}
            )
        
        weather_records = response.get('Items', [])
        
        # Sort by date (newest first)
        weather_records.sort(key=lambda x: x.get('date', ''), reverse=True)
        
        return render_template('weather.html', weather_records=weather_records)
    except Exception as e:
        flash(f'Error loading weather data: {str(e)}')
        return render_template('weather.html', weather_records=[])

@app.route('/weather/analytics')
@admin_required
def weather_analytics():
    try:
        # Get weather data for last 30 days
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()[:10]
        
        response = weather_table.scan()
        all_weather = response.get('Items', [])
        
        # Filter recent weather data
        recent_weather = [w for w in all_weather if w.get('date', '') >= thirty_days_ago]
        
        # Calculate statistics
        if recent_weather:
            avg_temp = sum(float(w.get('temperature', 0)) for w in recent_weather) / len(recent_weather)
            avg_humidity = sum(float(w.get('humidity', 0)) for w in recent_weather) / len(recent_weather)
            total_rainfall = sum(float(w.get('rainfall', 0)) for w in recent_weather)
            
            # Get unique locations
            locations = list(set(w.get('location', '') for w in recent_weather))
        else:
            avg_temp = avg_humidity = total_rainfall = 0
            locations = []
        
        stats = {
            'avg_temperature': avg_temp,
            'avg_humidity': avg_humidity,
            'total_rainfall': total_rainfall,
            'locations_count': len(locations),
            'records_count': len(recent_weather)
        }
        
        return render_template('weather_analytics.html', 
                             weather_records=recent_weather[:20], 
                             stats=stats,
                             locations=locations)
    except Exception as e:
        flash(f'Error loading weather analytics: {str(e)}')
        return render_template('weather_analytics.html', 
                             weather_records=[], 
                             stats={}, 
                             locations=[])

@app.route('/api/weather-stats')
@admin_required
def api_weather_stats():
    """API endpoint for weather statistics"""
    try:
        seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()[:10]
        
        response = weather_table.scan(
            FilterExpression='#date >= :date',
            ExpressionAttributeNames={'#date': 'date'},
            ExpressionAttributeValues={':date': seven_days_ago}
        )
        weather_data = response.get('Items', [])
        
        if weather_data:
            avg_temp = sum(float(w.get('temperature', 0)) for w in weather_data) / len(weather_data)
            avg_humidity = sum(float(w.get('humidity', 0)) for w in weather_data) / len(weather_data)
            total_rainfall = sum(float(w.get('rainfall', 0)) for w in weather_data)
        else:
            avg_temp = avg_humidity = total_rainfall = 0
        
        return jsonify({
            'avg_temperature': round(avg_temp, 1),
            'avg_humidity': round(avg_humidity, 1),
            'total_rainfall': round(total_rainfall, 1),
            'records_count': len(weather_data)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------------------------------------
# API Routes for Real-time Data
# ---------------------------------------
@app.route('/api/yield-stats')
@admin_required
def api_yield_stats():
    try:
        # Get yield data for last 30 days
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
        
        response = yield_data_table.scan(
            FilterExpression='created_at > :date',
            ExpressionAttributeValues={':date': thirty_days_ago}
        )
        yields = response.get('Items', [])
        
        total_yield = sum(float(y.get('yield_amount', 0)) for y in yields)
        avg_yield = total_yield / len(yields) if yields else 0
        anomaly_count = sum(1 for y in yields if y.get('is_anomaly', False))
        
        return jsonify({
            'total_yield': total_yield,
            'avg_yield': avg_yield,
            'anomaly_count': anomaly_count,
            'total_records': len(yields)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/farms/performance')
@admin_required
def api_farm_performance():
    try:
        response = farms_table.scan()
        farms = response.get('Items', [])
        
        performance_data = []
        for farm in farms:
            performance_data.append({
                'farm_name': farm.get('farm_name'),
                'location': farm.get('location'),
                'avg_yield': farm.get('avg_yield', 0),
                'crop_type': farm.get('crop_type'),
                'area_acres': farm.get('area_acres', 0)
            })
        
        return jsonify(performance_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------------------------------------
# Error Handlers
# ---------------------------------------
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal server error'), 500

# ---------------------------------------
# Main
# ---------------------------------------
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)