/*
 * Copyright (c) 2005-2007 Atheme Development Group
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Modifications by siniStar@IRC4Fun for the IRC4Fun network.
 *
 * AutoGline channels.
 *
 */

#include "atheme-compat.h"

DECLARE_MODULE_V1
(
	"contrib/os_glinechan", false, _modinit, _moddeinit,
	PACKAGE_STRING,
	"Jilles Tjoelker <http://www.stack.nl/~jilles/irc/>"
);

static void os_cmd_glinechan(sourceinfo_t *si, int parc, char *parv[]);
static void os_cmd_listglinechans(sourceinfo_t *si, int parc, char *parv[]);

command_t os_glinechan = { "GLINECHAN", "Glines all users joining a channel.",
			PRIV_MASS_AKILL, 3, os_cmd_glinechan, { .path = "contrib/glinechan" } };
command_t os_listglinechans = { "LISTGLINECHAN", "Lists active G:line channels.", PRIV_MASS_AKILL, 1, os_cmd_listglinechans, { .path = "contrib/listglinechans" } };

static void glinechan_check_join(hook_channel_joinpart_t *hdata);
static void glinechan_show_info(hook_channel_req_t *hdata);

void _modinit(module_t *m)
{
	service_named_bind_command("operserv", &os_glinechan);
	service_named_bind_command("operserv", &os_listglinechans);
	hook_add_event("channel_join");
	hook_add_first_channel_join(glinechan_check_join);
	hook_add_event("channel_info");
	hook_add_channel_info(glinechan_show_info);
}

void _moddeinit(module_unload_intent_t intent)
{
	service_named_unbind_command("operserv", &os_glinechan);
	service_named_unbind_command("operserv", &os_listglinechans);
	hook_del_channel_join(glinechan_check_join);
	hook_del_channel_info(glinechan_show_info);
}

static void glinechan_check_join(hook_channel_joinpart_t *hdata)
{
	mychan_t *mc;
	chanuser_t *cu = hdata->cu;
	service_t *svs;
	char reason[256];
	const char *khost;

	svs = service_find("operserv");
	if (svs == NULL)
		return;

	if (cu == NULL || is_internal_client(cu->user))
		return;

	if (!(mc = MYCHAN_FROM(cu->chan)))
		return;

	if (metadata_find(mc, "private:glinechan:closer"))
	{
		khost = cu->user->ip ? cu->user->ip : cu->user->host;
		if (has_priv_user(cu->user, PRIV_JOIN_STAFFONLY))
			notice(svs->me->nick, cu->user->nick,
					"WARNING: %s G-lines normal users",
					cu->chan->name);
		else if (is_autokline_exempt(cu->user))
		{
			char buf[BUFSIZE];
			snprintf(buf, sizeof(buf), "Not glining *@%s due to GLINECHAN %s (user %s!%s@%s is exempt)",
					khost, cu->chan->name,
					cu->user->nick, cu->user->user, cu->user->host);
			wallops_sts(buf);
		}
		else
		{
			snprintf(reason, sizeof reason, "AUTO) Joined banned Channel) %s",
					cu->chan->name);
			slog(LG_INFO, "glinechan_check_join(): G-lining \2*@%s\2 (user \2%s!%s@%s\2 joined \2%s\2)",
					khost, cu->user->nick,
					cu->user->user, cu->user->host,
					cu->chan->name);
			kline_sts("*", "*", khost, 432000, reason);
		}
	}
}

static void glinechan_show_info(hook_channel_req_t *hdata)
{
	metadata_t *md;
	const char *setter, *reason;
	time_t ts;
	struct tm tm;
	char strfbuf[BUFSIZE];

	if (!has_priv(hdata->si, PRIV_CHAN_AUSPEX))
		return;
	md = metadata_find(hdata->mc, "private:glinechan:closer");
	if (md == NULL)
		return;
	setter = md->value;
	md = metadata_find(hdata->mc, "private:glinechan:reason");
	reason = md != NULL ? md->value : "unknown";
	md = metadata_find(hdata->mc, "private:glinechan:timestamp");
	ts = md != NULL ? atoi(md->value) : 0;

	tm = *localtime(&ts);
	strftime(strfbuf, sizeof strfbuf, TIME_FORMAT, &tm);

	command_success_nodata(hdata->si, "%s had \2automatic Glines\2 enabled on it by %s on %s (%s)", hdata->mc->name, setter, strfbuf, reason);
}

static void os_cmd_glinechan(sourceinfo_t *si, int parc, char *parv[])
{
	char *target = parv[0];
	char *action = parv[1];
	char *reason = parv[2];
	mychan_t *mc;

	if (!target || !action)
	{
		command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GLINECHAN");
		command_fail(si, fault_needmoreparams, "Usage: GLINECHAN <#channel> <ON|OFF> [reason]");
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
			command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "GLINECHAN");
			command_fail(si, fault_needmoreparams, "Usage: GLINECHAN <#channel> ON <reason>");
			return;
		}

		if (mc->flags & CHAN_LOG)
		{
			command_fail(si, fault_noprivs, "\2%s\2 cannot be closed.", target);
			return;
		}

		if (metadata_find(mc, "private:glinechan:closer"))
		{
			command_fail(si, fault_nochange, "\2%s\2 is already on autokline.", target);
			return;
		}

		metadata_add(mc, "private:glinechan:closer", si->su->nick);
		metadata_add(mc, "private:glinechan:reason", reason);
		metadata_add(mc, "private:glinechan:timestamp", number_to_string(CURRTIME));

		wallops("%s enabled automatic Glines on the channel \2%s\2 (%s).", get_oper_name(si), target, reason);
		logcommand(si, CMDLOG_ADMIN, "GLINECHAN:ON: \2%s\2 (reason: \2%s\2)", target, reason);
		command_success_nodata(si, "G-lining all users joining \2%s\2.", target);
	}
	else if (!strcasecmp(action, "OFF"))
	{
		if (!metadata_find(mc, "private:glinechan:closer"))
		{
			command_fail(si, fault_nochange, "\2%s\2 is not closed.", target);
			return;
		}

		metadata_delete(mc, "private:glinechan:closer");
		metadata_delete(mc, "private:glinechan:reason");
		metadata_delete(mc, "private:glinechan:timestamp");

		wallops("%s disabled automatic Glines on the channel \2%s\2.", get_oper_name(si), target);
		logcommand(si, CMDLOG_ADMIN, "GLINECHAN:OFF: \2%s\2", target);
		command_success_nodata(si, "No longer G-lining users joining \2%s\2.", target);
	}
	else
	{
		command_fail(si, fault_badparams, STR_INVALID_PARAMS, "GLINECHAN");
		command_fail(si, fault_badparams, "Usage: GLINECHAN <#channel> <ON|OFF> [reason]");
	}
}

static void os_cmd_listglinechans(sourceinfo_t *si, int parc, char *parv[])
{
	const char *pattern;
	mowgli_patricia_iteration_state_t state;
	mychan_t *mc;
	metadata_t *md;
	int matches = 0;

	pattern = parc >= 1 ? parv[0] : "*";

	MOWGLI_PATRICIA_FOREACH(mc, &state, mclist)
	{
		md = metadata_find(mc, "private:glinechan:closer");
		if (md == NULL)
			continue;
		if (!match(pattern, mc->name))
		{
			command_success_nodata(si, "- %-30s", mc->name);
			matches++;
		}
	}

	logcommand(si, CMDLOG_ADMIN, "LISTGLINECHANS: \2%s\2 (\2%d\2 matches)", pattern, matches);
	if (matches == 0)
		command_success_nodata(si, _("No G:line channels matched pattern \2%s\2"), pattern);
	else
		command_success_nodata(si, ngettext(N_("\2%d\2 match for pattern \2%s\2"),
						    N_("\2%d\2 matches for pattern \2%s\2"), matches), matches, pattern);
}
