SUBDIRS = ./rtpencoder ../test 

.PHONY:all  
all:  
	mkdir -p ./target  
	mkdir -p ./rtpencoder/src/obj  
	mkdir -p ./test/src/obj  

	@list='$(SUBDIRS)';for subdir in $$list; do \
		cd $$subdir && make; \
	done

.PHONY:clean
clean:

	@list='$(SUBDIRS)';for subdir in $$list; do \
		cd $$subdir && make clean; \
	done  
	rm -rf ./target  
