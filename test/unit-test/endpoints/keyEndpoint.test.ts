// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Use the CCF polyfill to mock-up all key-value map functionality for unit-test
import "@microsoft/ccf-app/polyfill.js";
import { beforeAll, describe, expect, test } from "@jest/globals";
import { KeyGeneration, resolveKidQueryParam, toOhttpKeyId } from "../../../src";
import { hpkeKeyIdMap, hpkeKeysMap } from "../../../src/repositories/Maps";
import { LogContext } from "../../../src/utils/Logger";

// Seeds one HPKE key into the stores the same way refreshEndpoint does:
//   hpkeKeyIdMap:  sequential index -> wrappedKid
//   hpkeKeysMap:   wrappedKid       -> keyItem (keyItem.id is the 2-digit id)
// We set the maps directly (bypassing storeItem) to keep the unit test focused
// on resolution logic rather than CCF claims/receipts.
function seedKey(index: number, keyItemId: number, wrappedKid: string): void {
  const keyItem = KeyGeneration.generateKeyItem(keyItemId);
  keyItem.kid = wrappedKid;
  hpkeKeysMap.store.set(wrappedKid, keyItem);
  hpkeKeyIdMap.store.set(index, wrappedKid);
}

describe("keyEndpoint kid resolution", () => {
  const logContext = new LogContext().appendScope("keyEndpoint.test");

  // Two keys. Their on-the-wire OHTTP id is ToOhttpKeyId(keyItem.id), i.e. the
  // 2-digit id read as hex:
  //   id 26 -> 0x26 = 38   (matches production logs: keyItem.id 26 -> OHTTP 38)
  //   id 30 -> 0x30 = 48
  beforeAll(() => {
    seedKey(1, 26, "wrappedKidAlpha_1");
    seedKey(2, 30, "wrappedKidBeta_2");
  });

  test("toOhttpKeyId reads the 2-digit id as hex", () => {
    expect(toOhttpKeyId(26)).toEqual(38);
    expect(toOhttpKeyId(30)).toEqual(48);
    expect(toOhttpKeyId("26")).toEqual(38);
    // Too short to be a valid OHTTP-compatible id.
    expect(toOhttpKeyId(5)).toBeUndefined();
  });

  test("numeric OHTTP id resolves to the matching wrappedKid", () => {
    // Client/data-plane sends the OHTTP id "38"; it must map back to the
    // wrappedKid of the key whose keyItem.id is 26.
    expect(resolveKidQueryParam("38", logContext)).toEqual("wrappedKidAlpha_1");
    expect(resolveKidQueryParam("48", logContext)).toEqual("wrappedKidBeta_2");
  });

  test("non-numeric wrappedKid passes through unchanged", () => {
    // An explicit wrappedKid (base64url + _index, never all-digits) must be
    // returned as-is for backward compatibility.
    expect(resolveKidQueryParam("wrappedKidBeta_2", logContext)).toEqual(
      "wrappedKidBeta_2",
    );
    // Pass-through does not require the kid to exist in the store.
    expect(resolveKidQueryParam("some_unknown_wrappedKid", logContext)).toEqual(
      "some_unknown_wrappedKid",
    );
  });

  test("unknown numeric id resolves to undefined (endpoint returns 404)", () => {
    // No seeded key maps to OHTTP id 99, so resolution fails. The `key`
    // endpoint converts this undefined into a 404 "kid not found in store".
    expect(resolveKidQueryParam("99", logContext)).toBeUndefined();
  });
});
