PROTOS = client_token collection2v2 color_lyrics connectivity connect context devices duration extended_metadata extension_kind login5 metadata player playlist4_external playlist_permission playplay social_connect_v2 storage-resolve media context_page context_track restrictions entity_extension_data lens-model signal-model autoplay_context_request audio_files_extension

GEN = $(subst -,_,$(PROTOS:%=%_pb2.py) $(PROTOS:%=%_pb2.pyi))

all: gen libppdecrypt.so playhelp

playhelp: -lasound -lsndfile

up: all
	rsync -avhz *.py libppdecrypt.so minerva:spotify-sync

gen: $(GEN)

$(GEN): $(PROTOS:%=proto/%.proto)
	protoc -I=proto --python_out=. --pyi_out=. $^

lib%.so: %.c
	$(CC) $(CFLAGS) -shared $(LDFLAGS) $^ $(LDLIBS) -o $@

lib%.so: %.cc
	$(CXX) $(CXXFLAGS) -shared $(LDFLAGS) $^ $(LDLIBS) -o $@

.PHONY: all up gen clean

clean:
	rm -f $(GEN) libshn.so libppdecrypt.so playhelp
