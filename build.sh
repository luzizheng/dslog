
if [ ! -d "build" ]; then  
  mkdir build  
else  
  rm -rf build/*
fi
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make
#sudo make install