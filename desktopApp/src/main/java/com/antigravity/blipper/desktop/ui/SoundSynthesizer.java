package com.antigravity.blipper.desktop.ui;

import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.SourceDataLine;
import java.util.concurrent.atomic.AtomicBoolean;

public final class SoundSynthesizer {

    private static final float SAMPLE_RATE = 44_100f;

    private SoundSynthesizer() {}

    public static void playTaskCompletedChime() {
        Thread t = new Thread(() -> {
            playToneSequence(new int[]{587, 784, 1047}, new int[]{110, 110, 220}, 0.45, null);
        }, "blipper-chime-audio");
        t.setDaemon(true);
        t.start();
    }

    public static void playUrgentIntrusionSiren(AtomicBoolean stopSignal) {
        Thread t = new Thread(() -> {
            int[] freqs = new int[]{920, 1360, 920, 1360, 920, 1360, 920, 1360};
            int[] durs = new int[]{220, 220, 220, 220, 220, 220, 220, 220};
            playToneSequence(freqs, durs, 0.72, stopSignal);
        }, "blipper-siren-audio");
        t.setDaemon(true);
        t.start();
    }

    private static void playToneSequence(int[] frequenciesHz, int[] durationsMs, double volume, AtomicBoolean stopSignal) {
        AudioFormat format = new AudioFormat(SAMPLE_RATE, 16, 1, true, false);
        try (SourceDataLine line = AudioSystem.getSourceDataLine(format)) {
            line.open(format);
            line.start();
            for (int n = 0; n < frequenciesHz.length; n++) {
                if (stopSignal != null && stopSignal.get()) {
                    break;
                }
                int samples = (int) ((durationsMs[n] / 1000.0) * SAMPLE_RATE);
                byte[] buf = new byte[samples * 2];
                for (int i = 0; i < samples; i++) {
                    double angle = 2.0 * Math.PI * i * frequenciesHz[n] / SAMPLE_RATE;
                    double env = i < 400 ? (i / 400.0) : (i > samples - 400 ? ((samples - i) / 400.0) : 1.0);
                    short val = (short) (Math.sin(angle) * 32767.0 * volume * env);
                    buf[i * 2] = (byte) (val & 0xFF);
                    buf[i * 2 + 1] = (byte) ((val >> 8) & 0xFF);
                }
                line.write(buf, 0, buf.length);
            }
            line.drain();
        } catch (Exception ignored) {
            // Audio device unavailable or headless CI environment
        }
    }
}
