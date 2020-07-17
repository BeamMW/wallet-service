// Copyright 2018-2020 The Beam Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#pragma once

#include <memory>
#include "keykeeper/local_private_key_keeper.h"
#include "nlohmann/json.hpp"
#include "utility/logger.h"

namespace beam::wallet {
    using json = nlohmann::json;

    struct IKeykeeperConnection
    {
        using KeyKeeperFunc = std::function<void(const json&)>;
        virtual void invokeKeykeeperAsync(const json& msg, KeyKeeperFunc func) = 0;
    };

    class WasmKeyKeeperProxy
        : public PrivateKeyKeeper_WithMarshaller
        , public std::enable_shared_from_this<WasmKeyKeeperProxy>
    {
    public:
        WasmKeyKeeperProxy(Key::IPKdf::Ptr ownerKdf, std::weak_ptr<IKeykeeperConnection> connection);
        virtual ~WasmKeyKeeperProxy();

        Status::Type InvokeSync(Method::get_Kdf& x) override;
        Status::Type InvokeSync(Method::get_NumSlots& x) override;

        Status::Type InvokeSync(Method::CreateOutput& x) override {
            LOG_ERROR () << "Unexpected sync CreateOutput";
            assert(false);
            return Status::UserAbort;
        }

        Status::Type InvokeSync(Method::SignReceiver& x) override{
            LOG_ERROR () << "Unexpected sync SignReceiver";
            assert(false);
            return Status::UserAbort;
        }

        Status::Type InvokeSync(Method::SignSender& x) override{
            LOG_ERROR () << "Unexpected sync SignSender";
            assert(false);
            return Status::UserAbort;
        }

        Status::Type InvokeSync(Method::SignSplit& x) override{
            LOG_ERROR () << "Unexpected sync SignSplit";
            assert(false);
            return Status::UserAbort;
        }

        void InvokeAsync(Method::get_Kdf& x, const Handler::Ptr& h) override;
        void InvokeAsync(Method::get_NumSlots& x, const Handler::Ptr& h) override;
        void InvokeAsync(Method::CreateOutput& x, const Handler::Ptr& h) override;
        void InvokeAsync(Method::SignReceiver& x, const Handler::Ptr& h) override;
        void InvokeAsync(Method::SignSender& x, const Handler::Ptr& h) override;
        void InvokeAsync(Method::SignSplit& x, const Handler::Ptr& h) override;

        static void GetMutualResult(Method::TxMutual& x, const json& msg);
        static void GetCommonResult(Method::TxCommon& x, const json& msg);
        static Status::Type GetStatus(const json& msg);

        void cacheSbbsKdf (Key::Index idx, Key::IPKdf::Ptr kdf) {
            _sbbsKeyIdx = idx;
            _sbbsKdf = std::move(kdf);
        }

        void cacheSlots (IPrivateKeyKeeper2::Slot::Type slots) {
            _slots = slots;
        }

    private:
        std::weak_ptr<IKeykeeperConnection> _connection;

        //
        // Sync calls cache
        //

        // get owner kdf
        Key::IPKdf::Ptr _ownerKdf;

        // get sbbs kdf
        Key::Index      _sbbsKeyIdx = Key::Index(-1);
        Key::IPKdf::Ptr _sbbsKdf;

        // get num slots
        IPrivateKeyKeeper2::Slot::Type _slots = {0};
    };
}