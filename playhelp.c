#include <alsa/asoundlib.h>
#include <alsa/pcm.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sndfile.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define	BUFFER_LEN			(2048)
#define RATE 44100

#define log(...) fprintf(stderr, "\e[32;1m::\e[m " __VA_ARGS__)
#define warn(...) fprintf(stderr, "\e[31;1m::\e[m " __VA_ARGS__)

static snd_pcm_t *alsa_open(int channels, unsigned samplerate, int realtime) {
	const char *device = "default";
	snd_pcm_t *alsa_dev = NULL;
	snd_pcm_hw_params_t *hw_params;
	snd_pcm_uframes_t buffer_size;
	snd_pcm_uframes_t alsa_period_size, alsa_buffer_frames;
	snd_pcm_sw_params_t *sw_params;

	int err;

	if (realtime) {
		alsa_period_size = 256;
		alsa_buffer_frames = 3 * alsa_period_size;
	} else {
		alsa_period_size = 1024;
		alsa_buffer_frames = 4 * alsa_period_size;
	};

	if ((err = snd_pcm_open(&alsa_dev, device, SND_PCM_STREAM_PLAYBACK, 0)) < 0) {
		warn("cannot open audio device \"%s\" (%s)\n", device, snd_strerror(err));
		goto catch_error;
	};

	snd_pcm_nonblock(alsa_dev, 0);

	if ((err = snd_pcm_hw_params_malloc(&hw_params)) < 0) {
		warn("cannot allocate hardware parameter structure (%s)\n", snd_strerror(err));
		goto catch_error;
	};

	if ((err = snd_pcm_hw_params_any(alsa_dev, hw_params)) < 0) {
		warn("cannot initialize hardware parameter structure (%s)\n", snd_strerror(err));
		goto catch_error;
	};

	if ((err = snd_pcm_hw_params_set_access(alsa_dev, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED)) <
			0) {
		warn("cannot set access type (%s)\n", snd_strerror(err));
		goto catch_error;
	};

	if ((err = snd_pcm_hw_params_set_format(alsa_dev, hw_params, SND_PCM_FORMAT_FLOAT)) < 0) {
		warn("cannot set sample format (%s)\n", snd_strerror(err));
		goto catch_error;
	};

	if ((err = snd_pcm_hw_params_set_rate_near(alsa_dev, hw_params, &samplerate, 0)) < 0) {
		warn("cannot set sample rate (%s)\n", snd_strerror(err));
		goto catch_error;
	};

	if ((err = snd_pcm_hw_params_set_channels(alsa_dev, hw_params, channels)) < 0) {
		warn("cannot set channel count (%s)\n", snd_strerror(err));
		goto catch_error;
	};

	if ((err = snd_pcm_hw_params_set_buffer_size_near(alsa_dev, hw_params, &alsa_buffer_frames)) <
			0) {
		warn("cannot set buffer size (%s)\n", snd_strerror(err));
		goto catch_error;
	};

	if ((err = snd_pcm_hw_params_set_period_size_near(alsa_dev, hw_params, &alsa_period_size, 0)) <
			0) {
		warn("cannot set period size (%s)\n", snd_strerror(err));
		goto catch_error;
	};

	if ((err = snd_pcm_hw_params(alsa_dev, hw_params)) < 0) {
		warn("cannot set parameters (%s)\n", snd_strerror(err));
		goto catch_error;
	};

	/* extra check: if we have only one period, this code won't work */
	snd_pcm_hw_params_get_period_size(hw_params, &alsa_period_size, 0);
	snd_pcm_hw_params_get_buffer_size(hw_params, &buffer_size);
	if (alsa_period_size == buffer_size) {
		warn("Can't use period equal to buffer size (%lu == %lu)", alsa_period_size,
				buffer_size);
		goto catch_error;
	};

	snd_pcm_hw_params_free(hw_params);

	if ((err = snd_pcm_sw_params_malloc(&sw_params)) != 0) {
		warn("%s: snd_pcm_sw_params_malloc: %s", __func__, snd_strerror(err));
		goto catch_error;
	};

	if ((err = snd_pcm_sw_params_current(alsa_dev, sw_params)) != 0) {
		warn("%s: snd_pcm_sw_params_current: %s", __func__, snd_strerror(err));
		goto catch_error;
	};

	/* note: set start threshold to delay start until the ring buffer is full */
	snd_pcm_sw_params_current(alsa_dev, sw_params);

	if ((err = snd_pcm_sw_params_set_start_threshold(alsa_dev, sw_params, buffer_size)) < 0) {
		warn("cannot set start threshold (%s)\n", snd_strerror(err));
		goto catch_error;
	};

	if ((err = snd_pcm_sw_params(alsa_dev, sw_params)) != 0) {
		warn("%s: snd_pcm_sw_params: %s", __func__, snd_strerror(err));
		goto catch_error;
	};

	snd_pcm_sw_params_free(sw_params);

	snd_pcm_reset(alsa_dev);

catch_error:

	if (err < 0 && alsa_dev != NULL) {
		snd_pcm_close(alsa_dev);
		return NULL;
	};

	return alsa_dev;
}

int main(void) {
	SNDFILE *sf = NULL;
	SF_INFO sfinfo;

	snd_pcm_t *alsa_dev = alsa_open(2, RATE, 0);

	char line[256], *linep = line;
	char next[256];

	bool paused = 1;

	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	setlinebuf(stdin);
	setlinebuf(stdout);

	for (;;) {
		if (paused)
			poll(&(struct pollfd){STDIN_FILENO, POLLIN, 0}, 1, -1);
		int c;
		while (c = getchar(), c != EOF) {
			if (c != '\n') {
				*linep++ = c;
				continue;
			}
			*linep = 0;
			linep = line;
			log("got cmd: %c\n", line[0]);
			int64_t arg_ms = 0;
			switch (line[0]) {
			case 'n': // set next file
				strcpy(next, line+1);
				log("next is %s\n", next);
				break;
			case 'l': // load next
				arg_ms = strtol(line+1, NULL, 10);
			load_next:
				// TODO param: start time
				if (sf)
					sf_close(sf);
				memset(&sfinfo, 0, sizeof sfinfo);
				if (next[0] == '\0') {
				stop:
					sf = NULL;
					goto pause;
				}
				int64_t start_ms = strtol(line+1, NULL, 10);
				log("loading %s start = %ld\n", next, start_ms);
				sf = sf_open(next, SFM_READ, &sfinfo);
				printf("l\n");
				next[0] = '\0';
				if (sfinfo.channels != 2 || sfinfo.samplerate != RATE) {
					warn("unexpected sample rate / channel count!\n");
					sf_close(sf);
					memset(&sfinfo, 0, sizeof sfinfo);
					goto stop;
				}
				sf_seek(sf, sfinfo.samplerate * start_ms / 1000, SF_SEEK_SET);
				paused = 0;
				break;
			case 'p':
				paused = sf == NULL;
				if (!paused)
					printf("p\n");
				break;
			case 'P':
			pause:
				paused = 1;
				printf("P\n");
				break;
			case 's':
				arg_ms = strtol(line + 1, NULL, 10);
				if (sf)
					sf_seek(sf, sfinfo.samplerate * arg_ms / 1000, SF_SEEK_SET);
			default:
				break;
			}
		}
		if (paused)
			continue;

		static float buffer[BUFFER_LEN];
		sf_count_t rd = sf_read_float(sf, buffer, BUFFER_LEN);
		if (rd == 0) {
			printf("d\n");
			goto load_next;
		}
		int wr = snd_pcm_writei(alsa_dev, buffer, rd / sfinfo.channels);
		if (wr < 0) {
			wr = snd_pcm_recover(alsa_dev, wr, 0);
			if (wr == 0)
				snd_pcm_writei(alsa_dev, buffer, rd / sfinfo.channels);
		}
	}
}
