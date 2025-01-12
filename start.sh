#pip install -r requirements.txt
python3 network.py -d &
sleep 15 &&
echo "Network is ready" &&
python3 controllers/meta_controller.py