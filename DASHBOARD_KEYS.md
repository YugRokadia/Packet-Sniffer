# 🎮 Dashboard Keyboard Controls

## **Expand/Focus Panels:**

- **`1`** - Expand Protocol Distribution (shows top 20 protocols with bigger graph)
- **`2`** - Expand Top Talkers (shows top 30 IPs with full details)  
- **`3`** - Expand Top Domains (shows top 20 HTTPS domains)
- **`4`** - Expand DNS Queries (shows top 20 DNS queries)
- **`5`** - Expand Recent Packets (shows last 30 packets with full info)
- **`6`** - Expand Security Alerts

- **`0`** - Return to Overview (see all panels at once)

- **`Q`** - Quit dashboard

## **How It Works:**

When you press a number key (1-6), that panel **takes over the entire screen** with expanded data:
- **More rows** (10 → 30 items)
- **Wider columns** (see full IP addresses, long domains)
- **Bigger graphs** (protocol bars are longer)

Press **`0`** anytime to go back to the overview with all panels visible.

## **Example Usage:**

```bash
sudo python3 dashboard.py

# While running:
# Press '1' → See all protocols in detail
# Press '2' → See all top talkers with full IPs
# Press '5' → See full packet stream
# Press '0' → Back to overview
# Press 'q' → Exit
```

Enjoy! 🚀
