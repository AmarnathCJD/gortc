package media

import "context"

// MP4Options is retained for backwards compatibility; prefer EncodeOptions.
type MP4Options struct {
	VideoBitrateKbps int
	VideoWidth       int
	VideoHeight      int
	VideoFPS         int
	AudioBitrateKbps int
}

func (o MP4Options) toEncodeOptions() EncodeOptions {
	return EncodeOptions{
		VideoBitrateKbps: o.VideoBitrateKbps,
		VideoWidth:       o.VideoWidth,
		VideoHeight:      o.VideoHeight,
		VideoFPS:         o.VideoFPS,
		AudioBitrateKbps: o.AudioBitrateKbps,
	}
}

// StreamMP4 streams an MP4 (or any ffmpeg-decodable file) to the call.
// Deprecated: prefer Stream(ctx, send, audioSSRC, videoSSRC, FromFile(path)).
func StreamMP4(send AVSender, audioSSRC, videoSSRC uint32, filename string) error {
	return Stream(context.Background(), send, audioSSRC, videoSSRC, FromFile(filename))
}

// StreamMP4With streams a file with explicit encode options.
// Deprecated: prefer Stream with FromFile(path, opt).
func StreamMP4With(send AVSender, audioSSRC, videoSSRC uint32, filename string, opt MP4Options) error {
	return Stream(context.Background(), send, audioSSRC, videoSSRC, FromFile(filename, opt.toEncodeOptions()))
}
