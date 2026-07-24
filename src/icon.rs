use egui::IconData;

pub fn load_icon() -> IconData {
    let w = 32;
    let h = 32;
    let mut rgba = vec![0u8; w * h * 4];

    for y in 0..h {
        for x in 0..w {
            let i = (y * w + x) * 4;
            let cx = x as f64;
            let cy = y as f64;

            let left = 16.0 - (cy - 3.0) * 0.4;
            let right = 16.0 + (cy - 3.0) * 0.4;

            let in_a = cx >= left && cx <= right && cy >= 3.0 && cy <= 28.0;
            let crossbar = cy >= 16.0 && cy <= 19.0 && cx >= 11.0 && cx <= 21.0;
            let inner = cx >= left + 2.0 && cx <= right - 2.0 && cy >= 7.0 && cy <= 28.0 && !crossbar;

            if (in_a || crossbar) && !inner {
                rgba[i] = 0;
                rgba[i + 1] = 212;
                rgba[i + 2] = 255;
                rgba[i + 3] = 255;
            } else {
                rgba[i] = 26;
                rgba[i + 1] = 26;
                rgba[i + 2] = 46;
                rgba[i + 3] = 255;
            }
        }
    }

    IconData { rgba, width: w as u32, height: h as u32 }
}
