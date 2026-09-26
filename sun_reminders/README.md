# Sunrise / sunset light reminders

A reminder every day, weekends included, **30 minutes before sunrise** and
**30 minutes before sunset**, so there is time to get outside for the low,
red-orange light. It shows up on the iPhone and taps the Apple Watch.

Two ways to set it up. Pick one, not both, or you'll get every alert twice.

## Option A: iPhone Shortcuts (recommended, no server)

The iPhone works out sunrise and sunset from where you are each day, so the
times follow the seasons, daylight saving and travel on their own.

Create two automations in the **Shortcuts** app:

1. Open **Shortcuts** → **Automation** tab → **+** (or **New Automation**).
2. Choose **Time of Day**.
3. Select **Sunrise**, then set the offset to **30 minutes before sunrise**.
4. Make sure it repeats **Daily**.
5. Select **Run Immediately** (on older iOS: turn **Ask Before Running**
   off). Turning **Notify When Run** off avoids a second, generic banner.
6. Tap **Next** → **New Blank Automation** → **Add Action**. Search for
   **Show Notification** and set the text, for example:
   *"Sunrise in 30 minutes. Get outside for the morning light."*
7. Tap **Done**.

Repeat with **Sunset** → **30 minutes before sunset**, and a message like
*"Sunset in 30 minutes. Head outside for the evening light."*

**To get it on the Apple Watch:** notifications from the iPhone go to the
Watch when the iPhone is locked and the Watch is on your wrist. In the
**Watch** app on the iPhone, check that **Notifications → Shortcuts** is set
to mirror the iPhone.

**Don't let Sleep Focus hide the morning alert.** In summer, 30 minutes before
sunrise can be before 6 a.m. Go to **Settings → Focus → Sleep → Apps** and
add **Shortcuts** to the allowed apps.

**If you want it to ring like an alarm:** add a second action after
**Show Notification**: **Start Timer** with a duration of 1 second. The timer
goes off straight away with its ringtone.

## Option B: Home Assistant

Use this if the Home Assistant Companion app is on the iPhone. Sun times
come from the Home location set in Home Assistant.

1. In Home Assistant, go to **Developer tools → Actions** and search for
   `mobile_app` to find the phone's notify action, e.g.
   `notify.mobile_app_iphone`.
2. In [`home_assistant_automations.yaml`](home_assistant_automations.yaml),
   replace `notify.mobile_app_YOUR_IPHONE` with that action (it appears
   twice).
3. Add the two automations: paste them into `automations.yaml` and reload
   automations, or create each one in the UI with **Edit in YAML**.
4. On the iPhone, allow **Time Sensitive Notifications** for the Home
   Assistant app (Settings → Notifications → Home Assistant) so the alerts
   get through Focus modes.

Uses the `triggers:` / `actions:` syntax from Home Assistant 2024.10 and later.
