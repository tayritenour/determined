import { Map } from 'immutable';
import { observable, useObservable, WritableObservable } from 'micro-observables';
import React, { createContext, useEffect, useRef, useState } from 'react';

import { getUserSetting } from 'services/api';
import Spinner from 'shared/components/Spinner';
import { ErrorType } from 'shared/utils/error';
import authStore from 'stores/auth';
import userStore from 'stores/users';
import handleError from 'utils/error';
import { Loadable } from 'utils/loadable';

/*
 * UserSettingsState contains all the settings for a user
 * across the application. Each key identifies a unique part
 * of the interface to store settings for.
 */
type UserSettingsState = Map<string, Settings>;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Settings = { [key: string]: any }; //TODO: find a way to use a better type here

type UserSettingsContext = {
  clearQuerySettings: () => void;
  isLoading: WritableObservable<boolean>;
  querySettings: string;
  state: WritableObservable<UserSettingsState>;
};

export const UserSettings = createContext<UserSettingsContext>({
  clearQuerySettings: () => undefined,
  isLoading: observable(false),
  querySettings: '',
  state: observable(Map<string, Settings>()),
});

export const SettingsProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const currentUser = Loadable.getOrElse(undefined, useObservable(userStore.currentUser));
  const isAuthChecked = useObservable(authStore.isChecked);
  const [canceler] = useState(new AbortController());
  const [isLoading] = useState(() => observable(true));
  const querySettings = useRef('');
  const [settingsState] = useState(() => observable(Map<string, Settings>()));

  useEffect(() => {
    if (!isAuthChecked) return;

    try {
      getUserSetting({}, { signal: canceler.signal }).then((response) => {
        isLoading.set(false);
        settingsState.update((currentState) => {
          return currentState.withMutations((state) => {
            response.settings.forEach((setting) => {
              const value = setting.value ? JSON.parse(setting.value) : undefined;
              let key = setting.storagePath || setting.key; // falls back to the setting key due to storagePath being optional.

              if (key.includes('u:2/')) key = key.replace(/u:2\//g, '');

              const entry = state.get(key);
              if (!entry) {
                state.set(key, { [setting.key]: value });
              } else {
                state.set(key, Object.assign({}, entry, { [setting.key]: value }));
              }
            });
          });
        });
      });
    } catch (error) {
      handleError(error, {
        isUserTriggered: false,
        publicMessage: 'Unable to fetch user settings.',
        type: ErrorType.Api,
      });
    } finally {
      isLoading.set(false);
    }

    return () => canceler.abort();
  }, [canceler, isAuthChecked, isLoading, settingsState]);

  useEffect(() => {
    const url = window.location.search.substring(/^\?/.test(location.search) ? 1 : 0);

    querySettings.current = url;
  }, []);

  const clearQuerySettings = () => {
    querySettings.current = '';
  };

  return (
    <Spinner
      spinning={useObservable(isLoading) && !(isAuthChecked && !currentUser)}
      tip="Loading Page">
      <UserSettings.Provider
        value={{
          clearQuerySettings,
          isLoading: isLoading,
          querySettings: querySettings.current,
          state: settingsState,
        }}>
        {children}
      </UserSettings.Provider>
    </Spinner>
  );
};
