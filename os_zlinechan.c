/*
 * Copyright (c) 2014-2017 Xtheme Development Group
 * Rights to this code are as documented in doc/LICENSE.
 *
 * AutoZLINE channels. (or DLINE depending on IRCd) 
 * Effective on known botnet or drone channels, similar 
 * to os_akillchan except that it ZLINE's/DLINE's
 * instead of utilizing GLINE's/AKILL's.
 *
 * Default ZLINE time is 1 week (604800 seconds)
 *
 */

#include "atheme-compat.h"

DECLARE_MODULE_V1
(
	"contrib/os_zlinechan", false, _modinit, _moddeinit,
	PACKAGE_STRING,
	"Xtheme Group <www.Xtheme.org>"
);

static void os_cmd_zlinechan(sourceinfo_t *si, int parc, char *parv[]);
static void os_cmd_listzlinechans(sourceinfo_t *si, int parc, char *parv[]);

command_t os_zlinechan = { "ZLINECHAN", "ZLINEs/DLINEs all users joining a channel.",
			PRIV_MASS_AKILL, 3, os_cmd_zlinechan, { .path = "contrib/zlinechan" } };
command_t os_listzlinechans = { "LISTZLINECHAN", "Lists active ZLINE/DLINE channels.", PRIV_MASS_AKILL, 1, os_cmd_listzlinechans, { .path = "contrib/listzlinechans" } };

static void zlinechan_check_join(hook_channel_joinpart_t *hdata);
static void zlinechan_show_info(hook_channel_req_t *hdata);

void _modinit(module_t *m)
{
	service_named_bind_command("operserv", &os_zlinechan);
	service_named_bind_command("operserv", &os_listzlinechans);
	hook_add_event("channel_join");
	hook_add_first_channel_join(zlinechan_check_join);
	hook_add_event("channel_info");
	hook_add_channel_info(zlinechan_show_info);
}

void _moddeinit(module_unload_intent_t intent)
{
	service_named_unbind_command("operserv", &os_zlinechan);
	service_named_unbind_command("operserv", &os_listzlinechans);
	hook_del_channel_join(zlinechan_check_join);
	hook_del_channel_info(zlinechan_show_info);
}

static void zlinechan_check_join(hook_channel_joinpart_t *hdata)
{
	mychan_t *mc;
	chanuser_t *cu = hdata->cu;
	service_t *svs;
	char reason[256];
	const char *zhost;
	zline_t *z;

	svs = service_find("operserv");
	if (svs == NULL)
		return;

	if (cu == NULL || is_internal_client(cu->user))
		return;

	if (!(mc = mychan_from(cu->chan)))
		return;

	if (metadata_find(mc, "private:zlinechan:closer"))
	{
		zhost = cu->user->ip ? cu->user->ip : cu->user->host;
		if (has_priv_user(cu->user, PRIV_JOIN_STAFFONLY))
			notice(svs->me->nick, cu->user->nick,
					"Warning: %s ZLINEs normal users",
					cu->chan->name);
		else if (is_autokline_exempt(cu->user))
		{
			char buf[BUFSIZE];
			snprintf(buf, sizeof(buf), "Not adding ZLINE for *@%s due to zlinechan %s (user %s!%s@%s is exempt)",
					zhost, cu->chan->name,
					cu->user->nick, cu->user->user, cu->user->host);
			wallops_sts(buf);
		}
		else
		{
			snprintf(reason, sizeof reason, "Joined ZLINE channel %s",
					cu->chan->name);
			slog(LG_INFO, "zlinechan_check_join(): Adding ZLINE for \2*@%s\2 (user \2%s!%s@%s\2 joined \2%s\2)",
					cu->user->ip, cu->user->nick,
					cu->user->user, cu->user->ip,
					cu->chan->name);

			z = zline_add(cu->user->ip, reason, 604800, svs->me->nick);
		}
	}
}

static void zlinechan_show_info(hook_channel_req_t *hdata)
{
	metadata_t *md;
	const char *setter, *reason;
	time_t ts;
	struct tm tm;
	char strfbuf[BUFSIZE];

	if (!has_priv(hdata->si, PRIV_CHAN_AUSPEX))
		return;
	md = metadata_find(hdata->mc, "private:zlinechan:closer");
	if (md == NULL)
		return;
	setter = md->value;
	md = metadata_find(hdata->mc, "private:zlinechan:reason");
	reason = md != NULL ? md->value : "unknown";
	md = metadata_find(hdata->mc, "private:zlinechan:timestamp");
	ts = md != NULL ? atoi(md->value) : 0;

	tm = *localtime(&ts);
	strftime(strfbuf, sizeof strfbuf, TIME_FORMAT, &tm);

	command_success_nodata(hdata->si, "%s had \2automatic ZLINEs\2 enabled on it by %s on %s (%s)", hdata->mc->name, setter, strfbuf, reason);
}

static void os_cmd_zlinechan(sourceinfo_t *si, int parc, char *parv[])
{
	char *target = parv[0];
	char *action = parv[1];
	char *reason = parv[2];
	mychan_t *mc;

	if (!target || !action)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "ZLINECHAN");
		command_fail(si, fault_needmoreparams, "Usage: ZLINECHAN <#channel> <ON|OFF> [reason]");
		return;
	}

	if (!(mc = mychan_find(target)))
	{
		command_fail(si, fault_nosuch_target, "\2%s\2 is not registered.", target);
		return;
	}

	if (!strcasecmp(action, "ON"))
	{
		if (!reason)
		{
			command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "ZLINECHAN");
			command_fail(si, fault_needmoreparams, "Usage: ZLINECHAN <#channel> ON <reason>");
			return;
		}

		if (mc->flags & CHAN_LOG)
		{
			command_fail(si, fault_noprivs, "\2%s\2 cannot be closed.", target);
			return;
		}

		if (metadata_find(mc, "private:zlinechan:closer"))
		{
			command_fail(si, fault_nochange, "\2%s\2 is already a ZLINECHAN channel.", target);
			return;
		}

		if (metadata_find(mc, "private:klinechan:closer"))
		{
			command_fail(si, fault_nochange, "\2%s\2 is already an AKILLCHAN channel.", target);
			return;
		}

		metadata_add(mc, "private:zlinechan:closer", si->su->nick);
		metadata_add(mc, "private:zlinechan:reason", reason);
		metadata_add(mc, "private:zlinechan:timestamp", number_to_string(CURRTIME));

		wallops("%s enabled automatic zlines on the channel \2%s\2 (%s).", get_oper_name(si), target, reason);
		logcommand(si, CMDLOG_ADMIN, "ZLINECHAN:ON: \2%s\2 (reason: \2%s\2)", target, reason);
		command_success_nodata(si, "ZLINECHAN enabled for \2%s\2.", target);
	}
	else if (!strcasecmp(action, "OFF"))
	{
		if (!metadata_find(mc, "private:zlinechan:closer"))
		{
			command_fail(si, fault_nochange, "\2%s\2 is not a ZLINECHAN.", target);
			return;
		}

		metadata_delete(mc, "private:zlinechan:closer");
		metadata_delete(mc, "private:zlinechan:reason");
		metadata_delete(mc, "private:zlinechan:timestamp");

		wallops("%s disabled automatic zlines on the channel \2%s\2.", get_oper_name(si), target);
		logcommand(si, CMDLOG_ADMIN, "ZLINECHAN:OFF: \2%s\2", target);
		command_success_nodata(si, "ZLINECHAN disabled for \2%s\2.", target);
	}
	else
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "ZLINECHAN");
		command_fail(si, fault_badparams, "Usage: ZLINECHAN <#channel> <ON|OFF> [reason]");
	}
}

static void os_cmd_listzlinechans(sourceinfo_t *si, int parc, char *parv[])
{
	const char *pattern;
	mowgli_patricia_iteration_state_t state;
	mychan_t *mc;
	metadata_t *md;
	int matches = 0;

	pattern = parc >= 1 ? parv[0] : "*";

	MOWGLI_PATRICIA_FOREACH(mc, &state, mclist)
	{
		md = metadata_find(mc, "private:zlinechan:closer");
		if (md == NULL)
			continue;
		if (!match(pattern, mc->name))
		{
			command_success_nodata(si, "- %-30s", mc->name);
			matches++;
		}
	}

	logcommand(si, CMDLOG_ADMIN, "LISTZLINECHANS: \2%s\2 (\2%d\2 matches)", pattern, matches);
	if (matches == 0)
		command_success_nodata(si, _("No ZLINE channels matched pattern \2%s\2"), pattern);
	else
		command_success_nodata(si, ngettext(N_("\2%d\2 match for pattern \2%s\2"),
						    N_("\2%d\2 matches for pattern \2%s\2"), matches), matches, pattern);
}

