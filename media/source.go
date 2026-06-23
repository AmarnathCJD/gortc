// ────────────────────────────────────────────────────────────────────
//  gortc · Telegram Group-Call Streaming for Go  ·  © 2026 @amarnathcjd
//  https://github.com/amarnathcjd/gortc
// ────────────────────────────────────────────────────────────────────

package media

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ErrNotSeekable is returned by Player.Seek when the source cannot seek (e.g.
// reader or pre-encoded sources). Only FromFile/FromURL are seekable.
var ErrNotSeekable = errors.New("media: source is not seekable")

// Track selects which media a Source provides.
type Track int

const (
	TrackAudio Track = 1 << iota
	TrackVideo
)

func (t Track) Has(x Track) bool { return t&x != 0 }

// Streams is the encoded output of a Source: ogg/Opus audio and/or IVF/VP8
// video. A nil reader means that track is absent.
type Streams struct {
	Audio io.Reader
	Video io.Reader
	close func() error
}

func (s *Streams) Close() error {
	if s.close != nil {
		return s.close()
	}
	return nil
}

// Source produces encoded audio/video for a call. Build one with FromFile,
// FromURL, FromReader, FromOggOpus, FromIVF, FromRawPCM, or FromRawVideo.
type Source interface {
	Tracks() Track
	Open(ctx context.Context) (*Streams, error)
}

type VideoCodec int

const (
	VideoCodecVP8 VideoCodec = iota
	VideoCodecVP9
)

func (c VideoCodec) String() string {
	switch c {
	case VideoCodecVP9:
		return "VP9"
	default:
		return "VP8"
	}
}

func (c VideoCodec) MimeType() string {
	switch c {
	case VideoCodecVP9:
		return "video/VP9"
	default:
		return "video/VP8"
	}
}

type EncodeOptions struct {
	VideoCodec       VideoCodec
	VideoBitrateKbps int
	VideoWidth       int
	VideoHeight      int
	VideoFPS         int
	AudioBitrateKbps int
	// Tracks limits which tracks to produce. Zero means audio+video.
	Tracks Track
}

func (o EncodeOptions) withDefaults() EncodeOptions {
	if o.VideoBitrateKbps == 0 {
		o.VideoBitrateKbps = 500
	}
	if o.VideoWidth == 0 {
		o.VideoWidth = 854
	}
	if o.VideoHeight == 0 {
		o.VideoHeight = 480
	}
	if o.VideoFPS == 0 {
		o.VideoFPS = 30
	}
	if o.AudioBitrateKbps == 0 {
		o.AudioBitrateKbps = 510
	}
	if o.Tracks == 0 {
		o.Tracks = TrackAudio | TrackVideo
	}
	return o
}

var (
	Res480  = EncodeOptions{VideoWidth: 854, VideoHeight: 480, VideoBitrateKbps: 500, VideoFPS: 30}
	Res720  = EncodeOptions{VideoWidth: 1280, VideoHeight: 720, VideoBitrateKbps: 1500, VideoFPS: 30}
	Res1080 = EncodeOptions{VideoWidth: 1920, VideoHeight: 1080, VideoBitrateKbps: 3000, VideoFPS: 30}
)

func (o EncodeOptions) With(override EncodeOptions) EncodeOptions {
	if override.VideoCodec != 0 {
		o.VideoCodec = override.VideoCodec
	}
	if override.VideoBitrateKbps != 0 {
		o.VideoBitrateKbps = override.VideoBitrateKbps
	}
	if override.VideoWidth != 0 {
		o.VideoWidth = override.VideoWidth
	}
	if override.VideoHeight != 0 {
		o.VideoHeight = override.VideoHeight
	}
	if override.VideoFPS != 0 {
		o.VideoFPS = override.VideoFPS
	}
	if override.AudioBitrateKbps != 0 {
		o.AudioBitrateKbps = override.AudioBitrateKbps
	}
	if override.Tracks != 0 {
		o.Tracks = override.Tracks
	}
	return o
}

// RawAudioFormat describes raw PCM fed to FromRawPCM.
type RawAudioFormat struct {
	SampleRate int    // e.g. 48000
	Channels   int    // e.g. 2
	SampleFmt  string // ffmpeg sample fmt, e.g. "s16le" (default)
}

// RawVideoFormat describes raw frames fed to FromRawVideo.
type RawVideoFormat struct {
	Width    int
	Height   int
	FPS      int
	PixelFmt string // ffmpeg pixel fmt, e.g. "yuv420p" (default)
}

// --- ffmpeg argument builders -------------------------------------------------

func ffmpegAudioArgs(input []string, o EncodeOptions) []string {
	args := []string{"-hide_banner", "-loglevel", "error"}
	args = append(args, input...)
	filters := []string{
		"aresample=resampler=soxr:precision=28",
		"loudnorm=I=-16:LRA=11:TP=-1.5",
		"aresample=async=1000",
	}
	args = append(args,
		"-vn",
		"-af", strings.Join(filters, ","),
		"-c:a", "libopus",
		"-b:a", fmt.Sprintf("%dk", o.AudioBitrateKbps),
		"-vbr", "constrained",
		"-compression_level", "10",
		"-frame_duration", "20",
		"-page_duration", "20000",
		"-application", "audio",
		"-mapping_family", "0",
		"-ac", "2",
		"-ar", "48000",
		"-f", "ogg",
		"pipe:1",
	)
	return args
}

func ffmpegVideoArgs(input []string, o EncodeOptions) []string {
	rate := fmt.Sprintf("%dk", o.VideoBitrateKbps)
	gop := fmt.Sprintf("%d", o.VideoFPS*2)
	encoder := "libvpx"
	if o.VideoCodec == VideoCodecVP9 {
		encoder = "libvpx-vp9"
	}
	args := []string{"-hide_banner", "-loglevel", "error", "-re"}
	args = append(args, input...)
	args = append(args,
		"-an",
		"-c:v", encoder,
		"-b:v", rate, "-minrate", rate, "-maxrate", rate, "-bufsize", rate,
		"-rc_lookahead", "16",
		"-lag-in-frames", "16",
		"-vf", fmt.Sprintf("scale=%d:%d:force_original_aspect_ratio=decrease:force_divisible_by=2", o.VideoWidth, o.VideoHeight),
		"-r", fmt.Sprintf("%d", o.VideoFPS),
		"-g", gop, "-keyint_min", gop,
		"-auto-alt-ref", "0",
		"-error-resilient", "1",
		"-deadline", "realtime",
		"-cpu-used", "4",
		"-threads", "4",
		"-f", "ivf",
		"pipe:1",
	)
	return args
}

// SeekableSource is a Source that can start playback at an offset. FromFile and
// FromURL implement it; reader and pre-encoded sources do not.
type SeekableSource interface {
	Source
	OpenAt(ctx context.Context, offset time.Duration) (*Streams, error)
}

// probeDuration returns the total media duration via ffprobe, or 0 if it can't
// be determined (reader/pre-encoded sources, or ffprobe missing).
func probeDuration(src Source) time.Duration {
	ts, ok := src.(*transcodeSource)
	if !ok || ts.path == "" {
		return 0
	}
	out, err := exec.Command("ffprobe",
		"-v", "error",
		"-show_entries", "format=duration",
		"-of", "default=noprint_wrappers=1:nokey=1",
		ts.path,
	).Output()
	if err != nil {
		return 0
	}
	secs, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// transcodeSource runs ffmpeg to produce ogg/ivf from an arbitrary input.
// input is the ffmpeg -i argument set; stdin, if set, is wired to ffmpeg.
// path is the plain file/URL (seekable) when not using stdin.
type transcodeSource struct {
	input []string
	path  string
	stdin io.Reader
	opt   EncodeOptions
}

func (s *transcodeSource) Tracks() Track { return s.opt.withDefaults().Tracks }

func (s *transcodeSource) Open(ctx context.Context) (*Streams, error) {
	return s.open(ctx, s.input)
}

// OpenAt restarts ffmpeg seeking to offset (file/URL sources only).
func (s *transcodeSource) OpenAt(ctx context.Context, offset time.Duration) (*Streams, error) {
	if s.path == "" {
		return nil, ErrNotSeekable
	}
	input := []string{"-ss", strconv.FormatFloat(offset.Seconds(), 'f', 3, 64), "-i", s.path}
	return s.open(ctx, input)
}

func (s *transcodeSource) open(ctx context.Context, input []string) (*Streams, error) {
	o := s.opt.withDefaults()
	st := &Streams{}
	var procs []*exec.Cmd

	closeAll := func() error {
		for _, c := range procs {
			if c.Process != nil {
				_ = c.Process.Kill()
			}
		}
		return nil
	}

	start := func(args []string) (io.Reader, error) {
		cmd := exec.CommandContext(ctx, "ffmpeg", args...)
		if s.stdin != nil {
			cmd.Stdin = s.stdin
		}
		cmd.Stderr = nil
		out, err := cmd.StdoutPipe()
		if err != nil {
			return nil, err
		}
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		procs = append(procs, cmd)
		go func() { _ = cmd.Wait() }()
		return out, nil
	}

	if o.Tracks.Has(TrackAudio) {
		r, err := start(ffmpegAudioArgs(input, o))
		if err != nil {
			_ = closeAll()
			return nil, fmt.Errorf("start audio ffmpeg: %w", err)
		}
		st.Audio = r
	}
	if o.Tracks.Has(TrackVideo) {
		// A single stdin pipe cannot feed two ffmpeg processes, so a reader
		// source can't drive both audio and video; use a file/URL for that.
		if s.stdin != nil && o.Tracks.Has(TrackAudio) {
			_ = closeAll()
			return nil, fmt.Errorf("reader source cannot feed both audio and video; use FromFile/FromURL or pick one track")
		}
		r, err := start(ffmpegVideoArgs(input, o))
		if err != nil {
			_ = closeAll()
			return nil, fmt.Errorf("start video ffmpeg: %w", err)
		}
		st.Video = r
	}

	st.close = closeAll
	return st, nil
}

// --- Constructors -------------------------------------------------------------

// FromFile streams any ffmpeg-decodable file (mp4, mkv, webm, mov, ...).
func FromFile(path string, opt ...EncodeOptions) Source {
	return &transcodeSource{input: []string{"-i", path}, path: path, opt: first(opt)}
}

// FromURL streams from a URL or any ffmpeg-supported input (http, hls, rtmp, ...).
func FromURL(url string, opt ...EncodeOptions) Source {
	return &transcodeSource{input: []string{"-i", url}, path: url, opt: first(opt)}
}

// FromReader transcodes from an io.Reader via ffmpeg stdin. A single stdin
// cannot feed two encoders, so set opt.Tracks to one track, or use FromFile/FromURL.
func FromReader(r io.Reader, opt ...EncodeOptions) Source {
	return &transcodeSource{input: []string{"-i", "pipe:0"}, stdin: r, opt: first(opt)}
}

// FromRawPCM encodes raw PCM audio (no container) into Opus via ffmpeg.
func FromRawPCM(r io.Reader, f RawAudioFormat, opt ...EncodeOptions) Source {
	if f.SampleFmt == "" {
		f.SampleFmt = "s16le"
	}
	if f.SampleRate == 0 {
		f.SampleRate = 48000
	}
	if f.Channels == 0 {
		f.Channels = 2
	}
	o := first(opt)
	o.Tracks = TrackAudio
	input := []string{
		"-f", f.SampleFmt,
		"-ar", fmt.Sprintf("%d", f.SampleRate),
		"-ac", fmt.Sprintf("%d", f.Channels),
		"-i", "pipe:0",
	}
	return &transcodeSource{input: input, stdin: r, opt: o}
}

// FromRawVideo encodes raw video frames into VP8 via ffmpeg.
func FromRawVideo(r io.Reader, f RawVideoFormat, opt ...EncodeOptions) Source {
	if f.PixelFmt == "" {
		f.PixelFmt = "yuv420p"
	}
	if f.FPS == 0 {
		f.FPS = 30
	}
	o := first(opt)
	o.Tracks = TrackVideo
	if f.Width != 0 {
		o.VideoWidth = f.Width
	}
	if f.Height != 0 {
		o.VideoHeight = f.Height
	}
	o.VideoFPS = f.FPS
	input := []string{
		"-f", "rawvideo",
		"-pix_fmt", f.PixelFmt,
		"-s", fmt.Sprintf("%dx%d", f.Width, f.Height),
		"-r", fmt.Sprintf("%d", f.FPS),
		"-i", "pipe:0",
	}
	return &transcodeSource{input: input, stdin: r, opt: o}
}

// passthroughSource serves pre-encoded streams without ffmpeg.
type passthroughSource struct {
	audio io.Reader
	video io.Reader
}

func (s *passthroughSource) Tracks() Track {
	var t Track
	if s.audio != nil {
		t |= TrackAudio
	}
	if s.video != nil {
		t |= TrackVideo
	}
	return t
}

func (s *passthroughSource) Open(_ context.Context) (*Streams, error) {
	return &Streams{Audio: s.audio, Video: s.video}, nil
}

// FromOggOpus serves a pre-encoded ogg/Opus audio stream directly (no ffmpeg).
func FromOggOpus(r io.Reader) Source { return &passthroughSource{audio: r} }

// FromIVF serves a pre-encoded IVF/VP8 video stream directly (no ffmpeg).
func FromIVF(r io.Reader) Source { return &passthroughSource{video: r} }

// FromEncoded serves both a pre-encoded ogg/Opus and IVF/VP8 stream directly.
func FromEncoded(ogg, ivf io.Reader) Source {
	return &passthroughSource{audio: ogg, video: ivf}
}

func first(opt []EncodeOptions) EncodeOptions {
	if len(opt) > 0 {
		return opt[0]
	}
	return EncodeOptions{}
}
