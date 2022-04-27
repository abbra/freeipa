/*
 */

define([
        'dojo/on',
        './ipa',
        './jquery',
        './menu',
        './phases',
        './reg',
        './details',
        './search',
        './entity',
        './dialogs/password'
       ],
            function(on, IPA, $, menu, phases, reg) {

/**
 * Radius module
 * @class
 * @singleton
 */
var idp = IPA.idp = {};

var make_spec = function() {
return {
    name: 'idp',
    enable_test: function() {
        return true;
    },
    facets: [
        {
            $type: 'search',
            columns: [
                'cn',
                'ipaidpclientid',
                'ipaidpscope',
                'description'
            ]
        },
        {
            $type: 'details',
            sections: [
                {
                    name: 'details',
                    label: '@i18n:objects.idp.details',
                    fields: [
                        'cn',
                        {
                            $type: 'textarea',
                            name: 'description'
                        },
                        'ipaidpauthendpoint',
                        'ipaidpdevauthendpoint',
                        'ipaidptokendpoint',
                        'ipaidpuserinfodpoint',
                        'ipaidpkeysendpoint',
                        'ipaidpissuerurl',
                        'ipaidpclientid',
             {
                            name:'ipaidpclientsecret',
                            flags: ['w_if_no_aci']
                         }
                    ]
                }
            ],
            actions: [
                {
                    $type: 'password',
                    dialog: {
                        password_name: 'ipaidpclientsecret'
                    }
                }
            ],
            header_actions: ['password']
        }
    ],
    adder_dialog: {
        title: '@i18n:objects.idp.add',
        policies: [
            IPA.add_idp_policy
        ],
        fields: [
            'cn',
        {
        name: 'type',
        label: 'Provider type',
        $type: 'radio',
        flags: ['no_command'],
        layout: 'vertical',
        default_value: 'template',
        options: [
            {
                value: 'template',
                label: 'Pre-populated templates',
            },
            {
                value: 'custom',
                label: 'Custom',
            }
        ]
        },
            {
                label: '@i18n:idp.provider',
                name: 'ipaidpprovider',
                $type: 'select',
                options: IPA.create_options(['', 'google', 'github', 'microsoft', 'okta', 'keycloak'])
            },
            'ipaidpclientid',
            {
                $type: 'password',
                name: 'ipaidpclientsecret'
            },
            {
                $type: 'password',
                name: 'secret_verify',
                label: '@i18n:password.verify_password',
                flags: ['no_command'],
                required: true,
                validators: [{
                    $type: 'same_password',
                    other_field: 'ipaidpclientsecret'
                }]
            },
            'ipaidpscope',
            'ipaidpsub'
        ]
    },
    deleter_dialog: {
        title: '@i18n:objects.idp.remove'
    }
};};

IPA.add_idp_policy = function() {

    var that = IPA.facet_policy();

    that.init = function() {
        var type_f = that.container.fields.get_field('type');
        on(type_f, 'value-change', that.on_type_change);
    };

    that.on_type_change = function() {
        var type_f = that.container.fields.get_field('type');
        var mode = type_f.get_value()[0];
        var show_custom = true;
        var show_templates = true;

        // Pre-populated templates
        var ipaidpprovider_f = that.container.fields.get_field('ipaidpprovider');

        // Custom provider
        var ipaidpscope_f = that.container.fields.get_field('ipaidpscope');
        var ipaidpsub_f = that.container.fields.get_field('ipaidpsub');

        if (mode === 'template') show_custom = false;
        else if (mode === 'custom') show_templates = false;


        ipaidpprovider_f.set_enabled(show_templates);
        // ipaidpprovider_f.widget.set_visible(show_templates);

        ipaidpscope_f.set_enabled(show_custom);
        // ipaidpscope_f.widget.set_visible(show_custom);

        ipaidpsub_f.set_enabled(show_custom);
        // ipaidpsub_f.widget.set_visible(show_custom);

    };

    return that;
};

/**
 * Radius specification object
 */
idp.spec = make_spec();

/**
 * Register radiusproxy entity
 */
idp.register = function() {
    var e = reg.entity;
    e.register({type: 'idp', spec: idp.spec});
};

phases.on('registration', idp.register);

return idp;
});
