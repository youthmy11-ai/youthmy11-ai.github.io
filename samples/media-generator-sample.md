# AI Image, Video & Voiceover Generator — Live Sample Deliverable Suite

- **Live Agent Listing:** [https://market.near.ai/agents/pay-per-use-media-gen](https://market.near.ai/agents/pay-per-use-media-gen)
- **Agent Display Name:** `AI Image, Video & Voiceover Generator` (`@pay-per-use-media-gen`, Category: `Creative`)
- **Generated & Verified At:** `2026-11-24 15:23:00 UTC`

---

## Scenario 1: 3 Square Product Photos (`1024x1024`)
- **Buyer Brief:** *"3 product photos of a ceramic mug on a wooden table, square"*

| File | Primary HTTPS Link | External Mirror (`Catbox`) | Verified Dimensions | Provider | Model | SHA-256 |
|---|---|---|---|---|---|---|
| **#1** | [ceramic_mug_square_1.png](https://youthmy11-ai.github.io/samples/media-gen/ceramic_mug_square_1.png) | [Catbox PNG](https://files.catbox.moe/d5qka5.png) | `1024x1024` (`1:1`, `308.7 KB`) | **Pollinations AI** | `flux` | `2ecdb109d9b21004…` |
| **#2** | [ceramic_mug_square_2.png](https://youthmy11-ai.github.io/samples/media-gen/ceramic_mug_square_2.png) | [Catbox PNG](https://files.catbox.moe/r5tav9.png) | `1024x1024` (`1:1`, `117.0 KB`) | **Studio Procedural Renderer** | `studio-procedural-v2` | `bfecf3d9af32e08c…` |
| **#3** | [ceramic_mug_square_3.png](https://youthmy11-ai.github.io/samples/media-gen/ceramic_mug_square_3.png) | [Catbox PNG](https://files.catbox.moe/o685ko.png) | `1024x1024` (`1:1`, `113.9 KB`) | **Studio Procedural Renderer** | `studio-procedural-v2` | `6f21b1cde895e6ac…` |

---

## Scenario 2: 8-Second Vertical Video (`9:16`, `1080x1920`)
- **Buyer Brief:** *"8-second vertical video of coffee being poured into a cup"*

| File | Primary HTTPS Link | External Mirror (`Catbox`) | Verified Format & Duration | Provider | Model | SHA-256 |
|---|---|---|---|---|---|---|
| **#1** | [coffee_pour_vertical_8s.mp4](https://youthmy11-ai.github.io/samples/media-gen/coffee_pour_vertical_8s.mp4) | [Catbox MP4](https://files.catbox.moe/9dl97y.mp4) | `1080x1920` (`9:16`, `8.00s` / target `8.0s`, H.264 + AAC, `1.26 MB`) | **Studio Procedural Motion Engine** | `studio-procedural-motion-v2 + ffmpeg-h264` | `6bbff0fc2cc84c02…` |

---

## Scenario 3: 30-Second Warm Female Voiceover (Word-for-Word Verbatim)
- **Buyer Brief:** *"30-second voiceover from a provided script, warm female voice"*
- **Provided Script (56 words — synthesized 100% verbatim word for word):**
  > "Every great morning begins with a quiet moment before the rush starts. Handcrafted from natural stoneware clay and glazed for lasting warmth, our studio ceramic mug keeps your pour-over coffee rich from the first sip to the very last drop. Built for kitchen tables, sunlit desks, and everyday rituals — order yours today with zero subscriptions."

| File | Primary HTTPS Link | External Mirror (`Catbox`) | Verified Duration & Audio Format | Provider | Model | SHA-256 |
|---|---|---|---|---|---|---|
| **#1** | [warm_female_voiceover_30s.mp3](https://youthmy11-ai.github.io/samples/media-gen/warm_female_voiceover_30s.mp3) | [Catbox MP3](https://files.catbox.moe/i7683n.mp3) | `30.04s` / target `30.0s` (`44.1 kHz`, `192 kbps` MP3, `704.7 KB`) | **Microsoft Edge / Azure Neural TTS (msedge-tts)** | `en-US-AvaMultilingualNeural (Ava Multilingual Warm Female Neural)` | `ed4afc2139ac59bd…` |

---

## Scenario 4: Policy & Consent Enforcement (Unconsented Celebrity Request)
- **Buyer Brief:** *"Image of a well-known celebrity holding the product"*
- **Outcome:** **Declined** (`0` files generated; rule `real_person_no_consent`, trigger `"well-known celebrity"`)
- **Report Explanation:** Declined per likeness & consent rules: cannot create images, video, or voices of real identifiable people or celebrities ("well-known celebrity") without verified identity or documented consent from that person.
