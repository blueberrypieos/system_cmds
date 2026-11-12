/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 The Blueberry Pie OS Authors */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "open_directory.h"
#include "chpass.h"

static int
has_attribute(const ENTRY *ep, const CFStringRef *names, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (CFEqual(*ep->attrName, names[i]))
			return 1;
	return 0;
}

static CFTypeRef
first_value(CFDictionaryRef attrs, CFStringRef name)
{
	CFArrayRef values = attrs != NULL ? CFDictionaryGetValue(attrs, name) : NULL;

	if (values == NULL || CFGetTypeID(values) != CFArrayGetTypeID() || CFArrayGetCount(values) == 0)
		return NULL;
	return CFArrayGetValueAtIndex(values, 0);
}

static int
current_shell_allowed(CFDictionaryRef attrs)
{
	CFTypeRef shell = first_value(attrs, kODAttributeTypeUserShell);
	char *path;
	CFIndex size;
	int allowed = 0;

	if (shell == NULL || CFGetTypeID(shell) != CFStringGetTypeID())
		return 0;
	size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(shell), kCFStringEncodingUTF8) + 1;
	path = malloc(size);
	if (path != NULL && CFStringGetCString(shell, path, size, kCFStringEncodingUTF8))
		allowed = ok_shell(path);
	free(path);
	return allowed;
}

void
setrestricted(CFDictionaryRef attrs)
{
	const CFStringRef open_to_user[] = {
		kODAttributeTypeUserShell, kODAttributeTypeFullName, kODAttributeTypeBuilding,
		kODAttributeTypePhoneNumber, kODAttributeTypeHomePhoneNumber, kODAttributeTypePicture,
	};
	const CFStringRef closed_to_root[] = { kODAttributeTypePassword };
	ENTRY *ep;

	for (ep = list; ep->prompt != NULL; ep++) {
		if (master_mode)
			ep->restricted = has_attribute(ep, closed_to_root, 1);
		else if (CFEqual(*ep->attrName, kODAttributeTypeUserShell))
			ep->restricted = !current_shell_allowed(attrs);
		else
			ep->restricted = !has_attribute(ep, open_to_user,
			    sizeof(open_to_user) / sizeof(open_to_user[0]));
	}
}

static void
report(CFErrorRef error)
{
	CFStringRef text;

	if (error == NULL)
		return;
	if ((text = CFErrorCopyDescription(error)) != NULL) {
		cfprintf(stderr, "%s: %@", progname, text);
		CFRelease(text);
	}
	if ((text = CFErrorCopyFailureReason(error)) != NULL) {
		cfprintf(stderr, "  %@", text);
		CFRelease(text);
	}
	if ((text = CFErrorCopyRecoverySuggestion(error)) != NULL) {
		cfprintf(stderr, "  %@", text);
		CFRelease(text);
	}
	fputc('\n', stderr);
}

static CFStringRef
ask_password(CFStringRef name)
{
	CFStringRef prompt, password = NULL;
	CFIndex size;
	char *cprompt, *typed;

	prompt = CFStringCreateWithFormat(NULL, NULL, CFSTR("Password for %@: "), name);
	if (prompt == NULL)
		return NULL;
	size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(prompt), kCFStringEncodingUTF8) + 1;
	cprompt = malloc(size);
	if (cprompt != NULL && CFStringGetCString(prompt, cprompt, size, kCFStringEncodingUTF8) &&
	    (typed = getpass(cprompt)) != NULL) {
		password = CFStringCreateWithCString(NULL, typed, kCFStringEncodingUTF8);
		memset(typed, 0, strlen(typed));
	}
	free(cprompt);
	CFRelease(prompt);
	return password;
}

static int
on_local_node(void)
{
	return DSPath != NULL && CFStringHasPrefix(DSPath, CFSTR("/Local/"));
}

ODRecordRef
odGetUser(CFStringRef node_name, CFStringRef auth_name, CFStringRef name, CFDictionaryRef *details)
{
	const void *wanted[] = { kODAttributeTypeStandardOnly };
	CFArrayRef attributes;
	CFErrorRef err = NULL;
	CFStringRef password;
	ODNodeRef node;
	ODRecordRef record = NULL;
	CFTypeRef where;

	*details = NULL;
	if (node_name != NULL)
		node = ODNodeCreateWithName(NULL, kODSessionDefault, node_name, &err);
	else
		node = ODNodeCreateWithNodeType(NULL, kODSessionDefault, kODNodeTypeAuthentication, &err);
	if (node != NULL) {
		attributes = CFArrayCreate(NULL, wanted, 1, &kCFTypeArrayCallBacks);
		record = ODNodeCopyRecord(node, kODRecordTypeUsers, name, attributes, &err);
		if (attributes != NULL)
			CFRelease(attributes);
		CFRelease(node);
	}

	if (record != NULL) {
		*details = ODRecordCopyDetails(record, NULL, &err);
		where = first_value(*details, kODAttributeTypeMetaNodeLocation);
		DSPath = where != NULL && CFGetTypeID(where) == CFStringGetTypeID() ? where : NULL;

		if (auth_name != NULL || !master_mode || !on_local_node()) {
			if (auth_name == NULL)
				auth_name = name;
			password = ask_password(auth_name);
			if (password == NULL || !ODRecordSetNodeCredentials(record, auth_name, password, &err)) {
				CFRelease(record);
				record = NULL;
			}
			if (password != NULL)
				CFRelease(password);
		}
	}

	report(err);
	if (err != NULL)
		CFRelease(err);
	return record;
}

static int
unchanged(CFTypeRef before, CFTypeRef after)
{
	if (after == NULL || before == after)
		return 1;
	if (before == NULL)
		return CFGetTypeID(after) == CFStringGetTypeID() && CFStringGetLength(after) == 0;
	return CFEqual(before, after);
}

void
odUpdateUser(ODRecordRef record, CFDictionaryRef before, CFDictionaryRef edited)
{
	CFErrorRef err = NULL;
	CFArrayRef values;
	CFTypeRef after;
	ENTRY *ep;
	int changed = 0;

	if (record != NULL && before != NULL && edited != NULL) {
		for (ep = list; ep->prompt != NULL; ep++) {
			if (ep->restricted)
				continue;
			after = CFDictionaryGetValue(edited, *ep->attrName);
			if (unchanged(first_value(before, *ep->attrName), after))
				continue;
			values = CFArrayCreate(NULL, &after, CFEqual(after, CFSTR("")) ? 0 : 1,
			    &kCFTypeArrayCallBacks);
			if (values != NULL) {
				if (ODRecordSetValue(record, *ep->attrName, values, &err))
					changed = 1;
				CFRelease(values);
			}
			if (err != NULL) {
				report(err);
				CFRelease(err);
				err = NULL;
			}
		}
	}

	if (changed) {
		changed = ODRecordSynchronize(record, &err);
		if (err != NULL) {
			report(err);
			CFRelease(err);
		}
	}
	if (!changed)
		fprintf(stderr, "%s: no changes made\n", progname);
}
