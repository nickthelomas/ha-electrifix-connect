<p align="center"><img src="https://raw.githubusercontent.com/nickthelomas/ha-electrifix-connect/main/custom_components/electrifix_connect/brand/icon.png" width="96" alt="ElectriFix"></p>

# ElectriFix Connect

This is how ElectriFix looks at your Home Assistant while we work on your
job — safely, with your permission, and only for as long as the job lasts.

You do not need to open any ports, set up a tunnel, or create a token.

## What it does

When you add it, your Home Assistant makes **one outgoing connection** to
ElectriFix and holds it open — the same kind of connection your browser
makes to any website. Nothing is opened up at your end. Nobody can dial in.

Over that connection we read your setup so we can tell you what is wrong
with it, and — only after you have seen and approved a specific change —
make that change. When the job finishes, the connection closes and the
integration tells you it is safe to remove.

## Installing it

### With HACS (recommended)

1. In Home Assistant, open **HACS**.
2. Open the menu (top right) and choose **Custom repositories**.
3. Paste `https://github.com/nickthelomas/ha-electrifix-connect`, choose
   category **Integration**, and select **Add**.
4. Find **ElectriFix Connect** in the list and select **Download**.
5. **Restart Home Assistant** when it asks you to.

### Without HACS

Copy the `custom_components/electrifix_connect` folder from this repository
into your Home Assistant `config` folder, so you end up with
`config/custom_components/electrifix_connect/`, then restart Home Assistant.

## Setting it up

1. Go to **Settings → Devices & Services → Add Integration**.
2. Search for **ElectriFix Connect**.
3. Paste the **job code** from your ElectriFix job page and select
   **Submit**.

That is the whole setup. Your job page will notice within a few seconds and
move itself on.

If the code is not accepted, check you copied the whole thing — the copy
button on your job page is the safest way.

## What we can and cannot do

The integration carries a short, fixed list of requests and refuses
everything else, in your Home Assistant, before it happens:

**We can**

- read your entities, devices, areas, automations, logs and system health
- turn a specific automation on or off
- add or change an automation you have approved
- ask Home Assistant to take a backup before we change anything

**We cannot**

- unlock a lock, disarm an alarm, open a cover, or view a camera — ever,
  and there is no setting that changes this
- turn your lights, heating or appliances on and off
- read your cameras, recordings or microphones
- change anything you have not seen and approved first

Every change is proposed to you in writing, is backed up before it is made,
and is undone automatically if it does not work.

## Your credential stays in your house

The integration creates its own access token inside your Home Assistant. You
never make one, and never paste one into a web page.

**That token never leaves your Home Assistant.** ElectriFix never receives
it and never stores it. The integration uses it only to talk to your own
Home Assistant, on your own machine.

The token appears in your profile as **ElectriFix Connect**
(*Settings → People → your user → Refresh tokens*), so you can see it and
revoke it yourself at any time. We revoke it automatically when the job
finishes, and whenever you disable or remove the integration.

## Checking it is working

Go to **Settings → Devices & Services → ElectriFix Connect**. It adds one
sensor, **Connection**, which says whether it is connected right now.

If it says it is reconnecting, that is usually a brief internet drop — it
retries by itself, waiting a little longer each time, up to five minutes
between attempts. There is nothing for you to do.

## When the job is finished

The integration stops connecting on its own, revokes its token, and renames
itself **"Job finished — you can remove this integration"**.

At that point you can delete it: **Settings → Devices & Services →
ElectriFix Connect → ⋮ → Delete**. Nothing is left behind.

## Removing it at any time

You can remove it whenever you like, including mid-job — the access ends the
moment you do. Delete it the same way, or revoke its token from your profile.

## Questions

Reply to any email from your job, or raise an issue at
<https://github.com/nickthelomas/ha-electrifix-connect/issues>.
